package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	controllers "github.com/shaikhzidhin/controllers/Otp"
	Init "github.com/shaikhzidhin/initializer"
	"github.com/shaikhzidhin/models"
	"gorm.io/gorm"
)

var validate = validator.New()

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateRandomString(length int) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

var (
	setRedis            = Init.SetRedis
	getOtp              = controllers.GetOTP
	verifyOtp           = controllers.VerifyOTP
	getRedis            = Init.GetRedis
	create              = user.CreateUser
	fetchUserwalletById = walletref.FetchUserwalletById
	updatewallet        = walletref.Updatewallet
)

// Signup for user signup
func Signup(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Message": "binding error"})
		c.Abort()
		return
	}
	validationErr := validate.Struct(user)
	if validationErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "validation error"})
		return
	}

	if user.ReferralCode != "" {
		referreduser, err := fetchUserByRefferalCode(user.ReferralCode, Init.DB)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found in this referral code"})
			c.Abort()
			return
		}
		referreduser.Wallet.Balance += 50
	}

	if err := user.HashPassword(user.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "hashing error",
		})
		c.Abort()
		return
	}
	Otp := getOtp(user.Name, user.Email)

	jsonData, err := json.Marshal(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "false", "error": "Error encoding JSON"})
		return
	}

	// Inserting the OTP into Redis
	err = setRedis("signUpOTP"+user.Email, Otp, 5*time.Minute)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "false", "error": "Error inserting OTP in Redis client"})
		return
	}

	// Inserting the data into Redis
	err = setRedis("userData"+user.Email, jsonData, 5*time.Minute)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "false", "error": "Error inserting user data in Redis client"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"status": "true", "message": "Go to user/signup-verification"})
}

// SignupVerification for User OTP verification
func SignupVerification(c *gin.Context) {
	var otpCred models.OtpCredentials
	if err := c.ShouldBindJSON(&otpCred); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "binding error"})
		return
	}

	if verifyOtp("signUpOTP"+otpCred.Email, otpCred.Otp, c) {
		var userData models.User
		superKey := "userData" + otpCred.Email
		jsonData, err := getRedis(superKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "false", "error": "Error getting user data from Redis client"})
			return
		}
		err = json.Unmarshal([]byte(jsonData), &userData)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "false", "error": "Error binding Redis JSON data to user variable"})
			return
		}

		if userData.ReferralCode == "" {
			userData.ReferralCode = generateRandomString(10)
			// Create user and save transaction history and wallet balance
			err := create(&userData, Init.DB)
			if err != nil {
				c.JSON(400, gin.H{"Error": "USer creation Error"})
				return
			}

			c.JSON(200, gin.H{"status": "true", "message": "Otp Verification success. User creation done"})
			return
		}

		referredUser, err := fetchUserByRefferalCode(userData.ReferralCode, Init.DB)
		if err != nil {
			c.JSON(400, gin.H{"Error": "Error while fetching user"})
			return
		}
		// Update referred user's wallet balance
		wallet, err := fetchUserwalletById(referredUser.ID, Init.DB)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			// Handle unexpected errors
			c.JSON(500, gin.H{"Error": "Internal Server Error"})
			return
		}

		if wallet == nil {
			wallet = &models.Wallet{
				Balance: 0,
				UserID:  referredUser.ID,
			}
		} else {

			wallet.Balance += 100
			var transaction models.Transaction

			transaction.Amount = 100
			transaction.UserID = referredUser.ID
			transaction.Details = "Invite bonus added"
			transaction.Date = time.Now()

			fmt.Println("heeeeeeeeeeeeeeeeeeeeee")
			if err := createtransaction(Init.DB).Error; err != nil {
				c.JSON(400, gin.H{"Error": "Error while creating transaction"})
				return
			}
		}
		fmt.Println("helooooooooooooooooooooooooooo")

		// Save or update the wallet entry
		errr := updatewallet(Init.DB)
		if errr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "falsee", "Error": err})
			return
		}

		// Generate a new referral code for the current user
		userData.ReferralCode = generateRandomString(10)


		// Create user and save transaction history and wallet balance
		errrr := create(&userData, Init.DB)
		if errrr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "falsee", "Error": errrr})
			return
		}

		// var transaction models.Transaction
		transaction.Amount = 50
		transaction.UserID = userData.ID
		transaction.Details = "referal bonuse added"
		transaction.Date = time.Now()

		if err := createtransaction(Init.DB).Error; err != nil {
			c.JSON(400, gin.H{"Error": "Error while creating transaction"})
			return
		}

		c.JSON(http.StatusAccepted, gin.H{"status": "true", "message": "Otp Verification success. User creation done"})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "false", "message": "Invalid OTP"})
	}
}
