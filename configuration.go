/*
	Required that you specify Redis and Auth info, otherwise it won't work
*/

package oauth2_authenticator

import (
	"context"
	"github.com/go-redis/redis/v8"
	"net/http"
)

var ctx = context.Background()
var redisClient *redis.Client
var applicationIdAuth string //applicationID that identifies this project
var endPointOauthAuth string
var clientHttp *http.Client

func ConnectToRedis(host string, port string) {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: "",
		DB:       0,
	})
}

func ConnectToAuth(applicationId string, endPointOauth string) {
	applicationIdAuth = applicationId
	endPointOauthAuth = endPointOauth
	clientHttp = &http.Client{}
}
