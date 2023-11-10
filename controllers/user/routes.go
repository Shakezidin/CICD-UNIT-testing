package user

import (
	"github.com/gin-gonic/gin"
	"github.com/shaikhzidhin/middleware"
)

func RegisterUserRoutes(c *gin.Engine) {
	user := c.Group("/user")

	// User Authentication routes
	user.POST("/login", Login)
	user.POST("/signup", Signup)
	user.POST("/signup/verification", SignupVerification)

	// Password Recovery routes
	user.POST("/password/forget", ForgetPassword)
	user.POST("/password/forget/verifyotp", VerifyOTP)
	user.POST("/password/set/new", NewPassword)

	// User Home & Profile routes
	// user.Use(middleware.UserAuthMiddleware)
	user.GET("/", Home)
	user.GET("/profile", Profile)
	user.PATCH("/profile/edit", ProfileEdit)
	user.PUT("/profile/password/change", PasswordChange)
	user.GET("/booking/history", History)

	// Hotels routes
	user.GET("/home", Home)
	user.GET("/home/banner", BannerShowing)
	user.GET("/home/banner/hotel", ViewSpecificHotel)
	user.POST("/home/search", Searching)
	user.POST("/home/search/hotel", SearchHotelByName)

	// Room routes
	user.GET("/home/rooms", RoomsView)
	user.GET("/home/rooms/room", RoomDetails)
	user.POST("/home/rooms/filter", RoomFilter)

	// Contact routes
	user.POST("/home/contact", middleware.UserAuthMiddleware, SubmitContact)

	// Booking Management routes
	user.GET("/home/room/book", middleware.UserAuthMiddleware, CalculateAmountForDays)
	user.GET("/coupons/view", middleware.UserAuthMiddleware, ViewNonBlockedCoupons)
	user.GET("/coupon/apply", middleware.UserAuthMiddleware, ApplyCoupon)
	user.GET("/wallet", middleware.UserAuthMiddleware, ViewWallet)
	user.GET("/wallet/apply", middleware.UserAuthMiddleware, ApplyWallet)
	user.GET("/payat/hotel", middleware.UserAuthMiddleware, OfflinePayment)

	// Razorpay routes
	user.GET("/online/payment", RazorpayPaymentGateway)
	user.GET("/payment/success", RazorpaySuccess)
	user.GET("/success", SuccessPage)
	user.GET("/cancel/booking", CancelBooking)
}
