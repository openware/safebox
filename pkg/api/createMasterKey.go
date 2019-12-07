package api

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/buger/jsonparser"
	"github.com/openware/safebox/pkg/driver"
)

type createMasterParams struct {
	Driver string `json:"driver"`
}

func parseCreateMasterKeyParams(data []byte) (*createMasterParams, error) {
	p := &createMasterParams{}
	val, err := jsonparser.GetString(data, "driver")
	if err != nil {
		return nil, fmt.Errorf("Key driver not found")
	}
	p.Driver = val
	return p, nil
}

func CreateMasterKey(w http.ResponseWriter, r *http.Request) {
	data, _ := ioutil.ReadAll(r.Body)
	p, err := parseCreateMasterKeyParams(data)
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

	err = d.CreateMasterKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Error: %s", err))
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
	log.Println("Master key generated for ccy ", p.Driver)
}
