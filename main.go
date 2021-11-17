package main

import (
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
)

var (
	currentActiveKeysGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "gpg",
			Subsystem: "subkeys",
			Name:      "current",
			Help:      "Active GPG subkeys count: not expired at this time",
		}, []string{
			"name",
		})
	future1WeekActiveKeysGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "gpg",
			Subsystem: "subkeys",
			Name:      "future_1week",
			Help:      "Active GPG keys count: won't expire in a week",
		}, []string{
			"name",
		})
	future2WeeksActiveKeysGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "gpg",
			Subsystem: "subkeys",
			Name:      "future_2weeks",
			Help:      "Active GPG keys count: won't expire in two weeks",
		}, []string{
			"name",
		})
)

func getEnvDefault(name string, defaultVal string) string {
	envValue, ok := os.LookupEnv(name)
	if ok {
		return envValue
	}
	return defaultVal
}

func loop(dir, interval string) {
	intInterval, err := strconv.Atoi(interval)
	if err != nil {
		logrus.Error(err)
		intInterval = 15
	}

	ticker := time.NewTicker((time.Second * time.Duration(intInterval)))
	defer ticker.Stop()
	for ; true; <-ticker.C {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			logrus.Error(err)
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			pubkeyfile, err := os.Open(filepath.Join(dir, file.Name()))
			if err != nil {
				logrus.Error(err)
				continue
			}

			pubring, err := openpgp.ReadArmoredKeyRing(pubkeyfile)
			if err != nil {
				logrus.Error(err)
				continue
			}
			entity := pubring[0]

			timeNow := time.Now()
			timeNow1Week := time.Now().AddDate(0, 0, 7)
			timeNow2Weeks := time.Now().AddDate(0, 0, 14)
			validNowCount := 0
			valid1WeekCount := 0
			valid2WeeksCount := 0

			var maxTime time.Time
			for _, subkey := range entity.Subkeys {
				if subkey.Sig.FlagsValid &&
					subkey.Sig.FlagEncryptCommunications &&
					subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
					!subkey.Sig.KeyExpired(timeNow) &&
					(maxTime.IsZero() || subkey.Sig.CreationTime.After(maxTime)) {
					validNowCount += 1
				}
				if subkey.Sig.FlagsValid &&
					subkey.Sig.FlagEncryptCommunications &&
					subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
					!subkey.Sig.KeyExpired(timeNow1Week) &&
					(maxTime.IsZero() || subkey.Sig.CreationTime.After(maxTime)) {
					valid1WeekCount += 1
				}
				if subkey.Sig.FlagsValid &&
					subkey.Sig.FlagEncryptCommunications &&
					subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
					!subkey.Sig.KeyExpired(timeNow2Weeks) &&
					(maxTime.IsZero() || subkey.Sig.CreationTime.After(maxTime)) {
					valid2WeeksCount += 1
				}
			}

			currentActiveKeysGauge.WithLabelValues(file.Name()).Set(float64(validNowCount))
			future1WeekActiveKeysGauge.WithLabelValues(file.Name()).Set(float64(valid1WeekCount))
			future2WeeksActiveKeysGauge.WithLabelValues(file.Name()).Set(float64(valid2WeeksCount))
		}
	}
}

func init() {
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	prometheus.MustRegister(currentActiveKeysGauge)
	prometheus.MustRegister(future1WeekActiveKeysGauge)
	prometheus.MustRegister(future2WeeksActiveKeysGauge)
}

func main() {
	dir := getEnvDefault("GPG_KEYS_FOLDER", "/dev/shm/gpg")
	interval := getEnvDefault("INTERVAL", "15")
	listendAddr := getEnvDefault("HTTP_LISTENADDR", ":9112")

	go loop(dir, interval)

	http.Handle("/metrics", promhttp.Handler())
	logrus.Info("Now listening on ", listendAddr)
	logrus.Fatal(http.ListenAndServe(listendAddr, nil))
}
