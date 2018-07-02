package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jpillora/overseer"
	"github.com/mklimuk/auth/api"
	"github.com/mklimuk/auth/config"
	"github.com/mklimuk/auth/user"
	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"
)

var l *log.Entry

func SetLogger(logger *log.Logger) {
	l = logger.WithField("logger", "main")
}

func init() {
	SetLogger(log.StandardLogger())
}

//constants
const (
	defaultConfig   string = "/etc/auth/config.yml"
	defaultLogLevel string = "warn"
)

func main() {
	overseer.Run(overseer.Config{
		Program: auth,
		Address: ":8080",
	})
}

func auth(s overseer.State) {

	stop := make(chan os.Signal)
	signal.Notify(stop, os.Kill, os.Interrupt)

	v := viper.New()
	v.SetConfigName("config")
	v.AddConfigPath("/etc/auth")
	v.AddConfigPath("/usr/lib/auth/factory")

	v.SetDefault("loglevel", defaultLogLevel)
	v.SetDefault("versionfile", "/var/auth/version")
	v.SetDefault("storepath", "/var/auth/store")

	// watch config changes
	v.WatchConfig()
	v.OnConfigChange(updateConfig(v))

	var err error
	if err = v.ReadInConfig(); err != nil { // Handle errors reading the config file
		l.WithError(err).Panic("Could not read config file")
	}

	setLogLevel(v.GetString("loglevel"))
	config.ParseVersion(v.GetString("versionfile"))

	var store user.Store
	if store, err = user.NewBoltStore(v.GetString("storepath")); err != nil {
		l.WithError(err).Error("could not initialize store")
		os.Exit(1)
	}
	m := user.NewDefaultManager(store)

	l.Info("Initializing REST router")
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Route("/auth", api.UserAPI(m))
	r.Route("/control", api.ControlAPI())
	debug := v.GetBool("debug")
	if debug {
		r.Mount("/debug", middleware.Profiler())
	}
	hs := http.Server{Handler: r}
	go func() {
		hs.Serve(s.Listener)
	}()

	select {
	case <-s.GracefulShutdown:
		l.Infof("Graceful restart requested; cleaning up")
	case sig := <-stop:
		l.Infof("Stop signal %v received; shutting down", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs.Shutdown(ctx)
}

func updateConfig(v *viper.Viper) func(fsnotify.Event) {
	return func(e fsnotify.Event) {
		l.WithField("file", e.Name).Info("updating config from file")
		setLogLevel(v.GetString("loglevel"))
	}
}

func setLogLevel(level string) error {
	var (
		lvl log.Level
		err error
	)
	if lvl, err = log.ParseLevel(level); err != nil {
		l.WithFields(log.Fields{"requested": level, "existing": log.GetLevel()}).WithError(err).
			Error("could not parse the log level; keeping existing")
		return err
	}
	l.Infof("setting log level to %s", level)
	l.Logger.Level = lvl
	return nil
}
