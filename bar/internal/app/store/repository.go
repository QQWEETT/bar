package store

import "bar/internal/app/model"

type UserRepository interface {
	Create(*model.User) error
	Find(string) (*model.User, error)
	CreateDrinks(drink *model.Drink) error
	ShowDrinks(int) (model.Drinks, error)
	BuyDrink(d *model.Drink, user_id int) error
	PpmReduction()
	FindByLogin(string) (*model.User, error)
	CheckStatus(int)
}
