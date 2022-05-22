package apiserver

import (
	"bar/internal/app/model"
	"bar/internal/app/store"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

var (
	errIncorrectLoginOrPassword = errors.New("Incorrect login or password")
	jwtKey                      = []byte("my_secret_key")
)

type server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
}

type Claims struct {
	jwt.StandardClaims
	Login  string `json:"login"`
	UserId int    `json:"user_id"`
}

func newServer(store store.Store) *server {
	s := &server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store:  store,
	}
	s.configureRouter()
	go s.store.User().PpmReduction()
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.HandleFunc("/register", s.handleUsersCreate()).Methods("POST")
	s.router.HandleFunc("/login", s.handleSessionsCreate()).Methods("POST")
	s.router.HandleFunc("/me", s.checkMe()).Methods("GET")
	s.router.HandleFunc("/buy", s.buyDrink()).Methods("POST")
	s.router.HandleFunc("/add", s.add()).Methods("POST")
	s.router.HandleFunc("/list", s.list()).Methods("GET")
}

func (s *server) handleUsersCreate() http.HandlerFunc {
	type request struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u := &model.User{
			Login:    req.Login,
			Password: req.Password,
		}
		if err := s.store.User().Create(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		u.Sanitize()
		s.respond(w, r, http.StatusCreated, "Complete")

	}
}

func (s *server) handleSessionsCreate() http.HandlerFunc {
	type request struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		u, err := s.store.User().FindByLogin(req.Login)
		if err != nil || !u.ComparePassword(req.Password) {
			s.error(w, r, http.StatusUnauthorized, errIncorrectLoginOrPassword)
			return
		}
		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &Claims{
			Login:  u.Login,
			UserId: u.ID,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
		s.respond(w, r, http.StatusOK, nil)
	}
}

func (s *server) checkMe() http.HandlerFunc {

	claims := &Claims{}
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tknStr := c.Value
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		u, err := s.store.User().Find(claims.Login)
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		u.Sanitize()
		s.respond(w, r, http.StatusCreated, u)

	}
}

func (s *server) buyDrink() http.HandlerFunc {
	type request struct {
		Id int `json:"drinks_id"`
	}
	claims := &Claims{}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		d := &model.Drink{
			ID: req.Id,
		}
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tknStr := c.Value
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if claims.UserId > 1 {
			if err := s.store.User().BuyDrink(d, claims.UserId); err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
		} else {
			s.error(w, r, http.StatusUnprocessableEntity, err)
		}
		s.store.User().CheckStatus(claims.UserId)

		s.respond(w, r, http.StatusCreated, d)

	}

}

func (s *server) add() http.HandlerFunc {
	type request struct {
		Drink string  `json:"drink"`
		Price int     `json:"price"`
		Ppm   float32 `json:"ppm""`
	}
	claims := &Claims{}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		d := &model.Drink{
			Drink: req.Drink,
			Price: req.Price,
			Ppm:   req.Ppm,
		}
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tknStr := c.Value
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if claims.UserId == 1 {
			if err := s.store.User().CreateDrinks(d); err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
		} else {
			s.error(w, r, http.StatusUnprocessableEntity, err)
		}
		s.respond(w, r, http.StatusCreated, d)

	}
}

func (s *server) list() http.HandlerFunc {

	claims := &Claims{}
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tknStr := c.Value
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		u, err := s.store.User().ShowDrinks(claims.UserId)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		s.respond(w, r, http.StatusCreated, u)
	}

}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
