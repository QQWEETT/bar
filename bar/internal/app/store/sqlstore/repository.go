package sqlstore

import (
	"bar/internal/app/model"
	"bar/internal/app/store"
	"database/sql"
	"fmt"
	"time"
)

type UserRepository struct {
	store *Store
}

//register
func (r *UserRepository) Create(u *model.User) error {
	if err := u.Validate(); err != nil {
		return err
	}
	if err := u.BeforeCreate(); err != nil {
		return err
	}
	err := r.store.db.QueryRow(
		"INSERT INTO users (login, encrypted_password)  VALUES ($1,$2)  RETURNING user_id",
		u.Login,
		u.EncryptedPassword,
	).Scan(&u.ID)

	r.store.db.Query(
		"UPDATE users SET appointment =  case when user_id=1 then 'barman' when user_id>1 then 'client' end where user_id = $1",
		&u.ID)
	return err
}

// Create drink
func (r *UserRepository) CreateDrinks(u *model.Drink) error {
	return r.store.db.QueryRow(
		"INSERT INTO drinks (drink, price, ppm) VALUES ($1,$2,$3)  RETURNING drinks_id",
		u.Drink,
		u.Price,
		u.Ppm,
	).Scan(&u.ID)
}

// list drink
func (r *UserRepository) ShowDrinks(user_id int) (model.Drinks, error) {
	rows, err := r.store.db.Query(
		"select drinks_id, drink, price, drinks.ppm from drinks, users where users.user_id = $1 and  users.status = 'live'",
		user_id)
	if err != nil {
		panic(err)
	}
	drinks := model.Drinks{}
	for rows.Next() {
		d := &model.Drink{}
		if err := rows.Scan(&d.ID, &d.Drink, &d.Price, &d.Ppm); err != nil {
			fmt.Println(err)
			return nil, err
		}
		drinks = append(drinks, d)
	}
	return drinks, nil
}

//Buy drink
func (r *UserRepository) BuyDrink(d *model.Drink, user_id int) error {
	err := r.store.db.QueryRow("select drink, price, ppm from drinks where drinks_id=$1",
		d.ID).Scan(&d.Drink, &d.Price, &d.Ppm)
	if err != nil {
		panic(err)
	}
	return r.store.db.QueryRow(
		"UPDATE users SET balance = balance - $1, ppm = ppm + $2 where user_id = $3 and status = 'live' and balance > $1 RETURNING user_id",
		d.Price,
		d.Ppm,
		user_id,
	).Scan(&user_id)
}

//Check status
func (r *UserRepository) CheckStatus(user_id int) {
	rows, _ := r.store.db.Query("UPDATE users set status = case when ppm > 6 then 'dead' else 'live' end where user_id = $1",
		user_id)
	defer rows.Close()

}

// Log in
func (r *UserRepository) FindByLogin(login string) (*model.User, error) {
	u := &model.User{}
	if err := r.store.db.QueryRow(
		"SELECT user_id, login, encrypted_password FROM users WHERE login = $1",
		login,
	).Scan(
		&u.ID,
		&u.Login,
		&u.EncryptedPassword,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}
		return nil, err
	}

	return u, nil
}

//Me
func (r *UserRepository) Find(login string) (*model.User, error) {
	u := &model.User{}
	if err := r.store.db.QueryRow(
		"SELECT user_id, login, appointment,balance,ppm, encrypted_password FROM users WHERE login = $1 AND appointment = 'client' AND status = 'live'",
		login,
	).Scan(
		&u.ID,
		&u.Login,
		&u.Appointment,
		&u.Balance,
		&u.Ppm,
		&u.EncryptedPassword,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}
		return nil, err
	}

	return u, nil
}

// Ppm reduction
func (r *UserRepository) PpmReduction() {
	for i := 0; i < 1; i-- {
		time.Sleep(60 * time.Minute)

		rows, _ := r.store.db.Query("update users  SET ppm = ppm - case   when ppm > 1 then 1 else ppm end where status = 'live'")
		defer rows.Close()
	}

}
