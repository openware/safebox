package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/buger/jsonparser"
	"github.com/openware/safebox/pkg/driver"
)

const MaxUint = ^uint32(0)
const MaxInt = int64(MaxUint >> 1)

func parseCreateDepositAddressParams(data []byte) (*driver.CreateDepositAddressParams, error) {
	params := &driver.CreateDepositAddressParams{
		AccountID: -1,
	}

	err := jsonparser.ObjectEach(data, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {

		switch string(key) {
		case "account_id":
			if dataType.String() != "number" {
				return fmt.Errorf("unexpected type %s for driver expected %s", dataType.String(), "number")
			}
			id, err := jsonparser.ParseInt(value)
			if id < 0 || id > MaxInt {
				err = fmt.Errorf("Invalid account_id")
			}
			params.AccountID = int32(id)

			return err
		case "driver":
			if dataType.String() != "string" {
				return fmt.Errorf("unexpected type %s for driver expected %s", dataType.String(), "string")
			}
			params.Driver = string(value)
		case "uid":
			if dataType.String() != "string" {
				return fmt.Errorf("unexpected type %s for driver expected %s", dataType.String(), "string")
			}
			params.UID = string(value)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	if params.AccountID == -1 {
		return nil, fmt.Errorf("account_id is missing")
	}
	if params.Driver == "" {
		return nil, fmt.Errorf("driver is missing")
	}
	if params.UID == "" {
		return nil, fmt.Errorf("uid is missing")
	}

	return params, nil
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, message)
}

func CreateDepositAddress(w http.ResponseWriter, r *http.Request) {
	data, _ := ioutil.ReadAll(r.Body)
	p, err := parseCreateDepositAddressParams(data)
	var d driver.GenericDriver

	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Error: %s", err))
		return
	}

	switch p.Driver {
	case "btc":
		d = driver.NewBTC(p.Driver)

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Error: Unsupported driver %s", p.Driver))
		return
	}

	address, err := d.CreateDepositAddress(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Error: %s", err))
		return
	}

	json, err := json.Marshal(address)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Error: %s", err))
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
	log.Println(json)
}
