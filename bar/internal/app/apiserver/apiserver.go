package apiserver

import (
	"bar/internal/app/store/sqlstore"
	"database/sql"
	"net/http"
)

func Start(config *Config) error {
	db, err := newDB(config.DataBaseURL)

	if err != nil {
		return err
	}
	defer db.Close()
	store := sqlstore.New(db)
	s := newServer(store)

	return http.ListenAndServe(config.BindAddr, s)
}

func newDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
