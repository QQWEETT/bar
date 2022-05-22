package model

type Drink struct {
	ID    int     `json:"drinks_id"`
	Drink string  `json:"drink"`
	Price int     `json:"price"`
	Ppm   float32 `json:"ppm"`
}
type Drinks []*Drink
