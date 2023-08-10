package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Zackdan0227/gowebapp/models"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}
type DBStructure struct {
	Chirps      map[int]models.Chirp         `json:"chirps"`
	Users       map[int]models.User          `json:"users"`
	Revocations map[string]models.Revocation `json:"revocations"`
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	err := db.ensureDB()
	return db, err
}
func (db *DB) ResetDB() error {
	err := os.Remove(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return db.ensureDB()
}
func (db *DB) createDB() error {
	dbStructure := DBStructure{
		Chirps:      map[int]models.Chirp{},
		Users:       map[int]models.User{},
		Revocations: map[string]models.Revocation{},
	}
	return db.writeDB(dbStructure)
}

// CreateChirp creates a new models.Chirp and saves it to disk
func (db *DB) CreateChirp(body string, userID int) (models.Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return models.Chirp{}, err
	}
	id := len(dbStructure.Chirps) + 1
	chirp := models.Chirp{
		Id:        id,
		Body:      body,
		Author_id: userID,
	}
	dbStructure.Chirps[id] = chirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return models.Chirp{}, err
	}

	return chirp, nil
}

func (db *DB) CreateUser(body string, pass []byte) (models.User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return models.User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == body {
			return models.User{}, errors.New("email already taken")
		}
	}
	id := len(dbStructure.Users) + 1
	user := models.User{
		ID:       id,
		Email:    body,
		Password: pass,
	}
	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return models.User{}, err
	}

	return user, nil
}

func (db *DB) GetUserByEmail(email string) (models.User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return models.User{}, err
	}

	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}

	return models.User{}, errors.New("user not found")
}

func (db *DB) UpdateUser(userID string, email string, password []byte) (models.User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return models.User{}, err
	}
	id, err := strconv.Atoi(userID)
	if err != nil {
		return models.User{}, err
	}

	user, ok := dbStructure.Users[id]
	if !ok {
		return models.User{}, errors.New("user does not exist")
	}

	user.Email = email
	user.Password = password
	dbStructure.Users[id] = user
	err = db.writeDB(dbStructure)
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]models.Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	chirps := make([]models.Chirp, 0, len(dbStructure.Chirps))
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}
func (db *DB) DeleteChirpByID(chirpID int) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	if _, ok := dbStructure.Chirps[chirpID]; !ok {
		return fmt.Errorf("chirp with ID %d not found", chirpID)
	}

	delete(dbStructure.Chirps, chirpID)

	return nil
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return db.createDB()
	}
	return err
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStructure := DBStructure{}
	dat, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return dbStructure, err
	}

	err = json.Unmarshal(dat, &dbStructure)
	if err != nil {
		return dbStructure, err
	}

	return dbStructure, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dat, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, dat, 0600)

	if err != nil {
		return err
	}

	return nil
}

func (db *DB) RevokeToken(token string) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	revocation := models.Revocation{
		Token:     token,
		RevokedAt: time.Now().UTC(),
	}
	dbStructure.Revocations[token] = revocation

	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) IsTokenRevoked(token string) (bool, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return false, err
	}

	revocation, ok := dbStructure.Revocations[token]
	if !ok {
		return false, nil
	}

	if revocation.RevokedAt.IsZero() {
		return false, nil
	}

	return true, nil
}
