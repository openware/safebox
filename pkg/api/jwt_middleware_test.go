package api

import (
	"io/ioutil"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestExtractTokenFromHeader(t *testing.T) {

	t.Run("valid header", func(t *testing.T) {
		header := "Bearer ABCD"
		assert.Equal(t, "ABCD", extractTokenFromHeader(header))
	})

	t.Run("valid header with a space", func(t *testing.T) {
		header := " Bearer ABCD"
		assert.Equal(t, "ABCD", extractTokenFromHeader(header))
	})

	t.Run("invalid header", func(t *testing.T) {
		header := "abcd"
		assert.Equal(t, "", extractTokenFromHeader(header))
	})
}

func TestParseJWT(t *testing.T) {
	FakeKeyFunc := func(keyName string) func(_ *jwt.Token) (interface{}, error) {
		return func(_ *jwt.Token) (interface{}, error) {
			pub, err := ioutil.ReadFile("../../fixtures/" + keyName + ".key.pub")
			assert.NoError(t, err)
			signingKey, err := jwt.ParseRSAPublicKeyFromPEM(pub)
			assert.NoError(t, err)
			return signingKey, nil
		}
	}

	t.Run("Invalid token", func(t *testing.T) {
		claims, err := ParseJWT("x.y", FakeKeyFunc("sample"))
		assert.Equal(t, "token contains an invalid number of segments", err.Error())
		assert.Nil(t, claims)
	})

	t.Run("Valid token", func(t *testing.T) {
		token := "eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE1NzUwNDU0ODAsImV4cCI6MTU3NTA4MTQ4MCwic3ViIjoic2Vzc2lvbiIsImlzcyI6ImJhcm9uZyIsImp0aSI6IjExMTExMTExMTEiLCJ1aWQiOiJJREFCQzAwMDAwMDEiLCJlbWFpbCI6ImFkbWluQGJhcm9uZy5pbyIsInJvbGUiOiJhZG1pbiIsImxldmVsIjozLCJzdGF0ZSI6ImFjdGl2ZSIsInJlZmVycmFsX2lkIjpudWxsfQ.AZXLXuitWXC9lGldLxI9uy0iolpD7en7AiutA_Ahb7bkoQ73L4_uXBOeC0GyJFoXqtKNdkr-rSNDDGAfpcCxNxA6D4p2vjrrsOaQxUm4qgb12702w1wYRjdyHso_IETbiF_HUNcEoaMBLV-YKBSvuNkt5ypIrhcDvtQvpmczZ9j57uHsOCAL7OahkUjnduqczODovr8rFY2yxZ8khu0MJ4ND2iHTDR8lUlJ44a9Rw_WFewF_edzLBS9WWQYz_7TllEov5fozm9rL0cD0pmotIJdabOdwX76zaIITxU1zRdDtNST-10lVKDjvM2kb59Du92Yhr-CuFCae9Z6I6fz_kw"
		claims, err := ParseJWT(token, FakeKeyFunc("sample"))

		assert.NoError(t, err)
		assert.NotNil(t, claims.UID)
		assert.Equal(t, "IDABC0000001", claims.UID)
		assert.Equal(t, "admin@barong.io", claims.Email)
		assert.Equal(t, 3, claims.Level)
	})

	t.Run("Invalid token: bad signer", func(t *testing.T) {
		token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJiYXJvbmciLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMCIsImlhdCI6MTU0NzgwMzE5MCwiZXZlbnQiOnsidXNlciI6eyJ1aWQiOiJJRDAxMjM0NTY3ODkiLCJlbWFpbCI6ImpvaG5AZG9lLmNvbSIsInJvbGUiOiJtZW1iZXIiLCJsZXZlbCI6MCwib3RwIjpmYWxzZSwic3RhdGUiOiJwZW5kaW5nIiwiY3JlYXRlZF9hdCI6IjIwMTktMDEtMThUMDk6MTk6NTBaIiwidXBkYXRlZF9hdCI6IjIwMTktMDEtMThUMDk6MTk6NTBaIn0sInRva2VuIjoiZXlKaGJHY2lPaUpTVXpJMU5pSjkuZXlKcFlYUWlPakUxTkRjNE1ETXhPVEFzSW1WNGNDSTZNVFUwTnpnd09URTVNQ3dpYzNWaUlqb2lZMjl1Wm1seWJXRjBhVzl1SWl3aWFYTnpJam9pWW1GeWIyNW5JaXdpWVhWa0lqcGJJbkJsWVhScGJ5SXNJbUpoY205dVp5SmRMQ0pxZEdraU9pSmxZelUzWkdVME1EUXlNREF6TVdSak5XUTJNQ0lzSW1WdFlXbHNJam9pWVdSdGFXNHlRR0poY205dVp5NXBieUlzSW5WcFpDSTZJa2xFTWpnMk5UZEJPVVF5T1NKOS5XUU1aS0FyR2NlMlZGb19zMW1WeHJQajdNREhhSGhSYmtzNk9IV2xTMThEcTBnZVl2UHMybmZKT3JuTnBxMk1SekpJQ0U1SE9KNHlnenIwYkFPSURCcWZ5X1ZRTEl2WFc3aENiWmdDQ1NFcjFSaVpaTGQ2R2hBY1EtbHM1RzY3WEY2S3RKNUlpOVY3djFZckIxVnpnRGhtZ1RRdUZLbmxuMGMtMWhhUlRzTVU3ZW9NUVhYT1ppdXNWM28xZ0ViemJiMUlFNTF6ZlNzb0wxMFZrXzJRNjAxZmdEc3d2V1ZQcE5CVFFVT2pQRkFZSEZWaGxGaENJOHkyV09jY3NJUGw5aWdnSEFVQ3E5ZGlZLTVLTjlTeW9WSFUyMUtSZWZ1QV8yRzJiTzBpV3lQZG9vaDBTVDI0Y2s4RXNFRG5NT2J3M0xjdlBvNFQ3LU85UFM4bkM2N09JeGciLCJuYW1lIjoic3lzdGVtLnVzZXIuZW1haWwuY29uZmlybWF0aW9uLnRva2VuIn0sImFsZyI6IlJTMjU2In0.kWPCnUdQQLNxdzRTX-NLy-kJY8qk5XpT65H2gjXv0Q4P-Q8mxkUdL3-Bdy0yy13C1bSnQS-yPnRG4jX_-G0Xdj1eKhtSk7sVf44K5ggcopCsWZ4b1eIoAWTtXpABHQo2Po5zUGjOClzljWv3uJhMKXhK4veSfPqFwSfE9IFPyvJ3FLnCVHgfD_rm5pikgqR-ya--zk6V1RjCe0442xKH5Sx-XBOlulMMr-CQ04k09Vawy-W80y2WsNugjMdDr0ZHjCnOjLcm0Hayy9kSql9UTln7o8wcSEVMDum-EIBadohM-9q_f2gXVRNuOg2gR7sbA9mGwsut-sBcR8IBmyPzuQ"
		claims, err := ParseJWT(token, FakeKeyFunc("sample2"))

		assert.Equal(t, "crypto/rsa: verification error", err.Error())
		assert.Nil(t, claims)
	})
}
