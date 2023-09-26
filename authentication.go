/*
	Create a Gin-Gonic middleware for oauth2 authentication
	Use Redis as a cache in which store an oauth2 authentication for 1 hour
	Insert in gin.Context user_id (*DataReceive)
	Insert in gin.Context user_roles ([]string)
*/

package oauth2_authenticator

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

/*
Json of api/user
*/
type DataReceive struct {
	User struct {
		Active                    bool   `json:"active"`
		ConnectorID               string `json:"connectorId"`
		Email                     string `json:"email"`
		FullName                  string `json:"fullName"`
		ID                        string `json:"id"`
		InsertInstant             int64  `json:"insertInstant"`
		LastLoginInstant          int64  `json:"lastLoginInstant"`
		LastUpdateInstant         int64  `json:"lastUpdateInstant"`
		PasswordChangeRequired    bool   `json:"passwordChangeRequired"`
		PasswordLastUpdateInstant int64  `json:"passwordLastUpdateInstant"`
		Registrations             []struct {
			ApplicationID     string   `json:"applicationId"`
			ID                string   `json:"id"`
			InsertInstant     int64    `json:"insertInstant"`
			LastLoginInstant  int64    `json:"lastLoginInstant"`
			LastUpdateInstant int64    `json:"lastUpdateInstant"`
			Roles             []string `json:"roles"`
			UsernameStatus    string   `json:"usernameStatus"`
			Verified          bool     `json:"verified"`
		} `json:"registrations"`
		TenantID          string `json:"tenantId"`
		TwoFactorDelivery string `json:"twoFactorDelivery"`
		TwoFactorEnabled  bool   `json:"twoFactorEnabled"`
		UsernameStatus    string `json:"usernameStatus"`
		Verified          bool   `json:"verified"`
	} `json:"user"`
}

/*
Gin-Gonic middleware to import for oauth2 authentication
*/
func Authentication(c *gin.Context) {
	var authorization string
	if c.GetHeader("Authorization") == "" {
		authorization = "Bearer " + c.Request.URL.Query().Get("token")
	} else {
		authorization = c.GetHeader("Authorization")
	}
	userInfo := redisClient.Get(ctx, createKey(authorization))

	if userInfo.Val() == "" {
		keyRedisNotExist(c, authorization)
	} else {
		keyRedisExists(c, userInfo)
	}
}

/*
Gin-Gonic middleware to import for check roles of an user
it MUST be used after Authentication
*/
func Roles(roles []string) func(c *gin.Context) {
	return func(c *gin.Context) {
		var rolesUser []string
		canContinue := false
		rolesUser = c.MustGet("user_roles").([]string)
		for _, role := range roles {
			if isInArray(role, rolesUser) {
				canContinue = true
				break
			}
		}
		if canContinue {
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
		}
	}
}

/*
Simple function to check if a value is in an array
*/
func isInArray(value string, arrayValues []string) bool {
	for _, arrayValue := range arrayValues {
		if value == arrayValue {
			return true
		}
	}
	return false
}

/*
If the Redis key doesn't exist, it creates and use it
*/
func keyRedisNotExist(c *gin.Context, authorization string) {
	request, _ := http.NewRequest("GET", endPointOauthAuth+"/api/user", nil)
	request.Header.Add("Authorization", authorization)
	response, err := clientHttp.Do(request)

	if err != nil || response.StatusCode != 200 {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
	} else {
		var send DataReceive

		body, _ := ioutil.ReadAll(response.Body)
		if err := json.Unmarshal(body, &send); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
		} else {
			roles := checkApplicationIDAndGetRules(&send)
			if roles == nil {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
			} else {
				token, _, _ := new(jwt.Parser).ParseUnverified(authorization[7:], jwt.MapClaims{})
				claims, _ := token.Claims.(jwt.MapClaims)
				expTime := int64(claims["exp"].(float64)) * 1000
				expirationJwt := time.Duration(expTime-time.Now().UnixNano()) / 2 * time.Nanosecond
				fmt.Println("expTime", expTime)
				fmt.Println("expiration", expirationJwt)

				redisClient.Set(ctx, createKey(authorization), string(body), expirationJwt)
				c.Set("user_id", &send)
				c.Set("user_roles", roles)
				c.Next()
			}
		}
	}
}

/*
It uses the data in the Redis key
*/
func keyRedisExists(c *gin.Context, userInfo *redis.StringCmd) {
	var send DataReceive
	text := userInfo.Val()
	if err := json.Unmarshal([]byte(text), &send); err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
	} else {
		roles := checkApplicationIDAndGetRules(&send)
		c.Set("user_id", &send)
		c.Set("user_roles", roles)
		c.Next()
	}
}

/*
Check if the application ID of the user is equal to the application ID of the project
*/
func checkApplicationIDAndGetRules(data *DataReceive) []string {
	for _, registration := range data.User.Registrations {
		if registration.ApplicationID == applicationIdAuth {
			return registration.Roles
		}
	}
	return nil
}

/*
Create the key for Redis
*/
func createKey(authentication string) string {
	index := strings.LastIndex(authentication, ".") + 1
	return "oauth2.authenticator:" + authentication[index:]
}
