package main	

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()	

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Api está online!",
		})
	})	

	r.Run(":8080")

	database.Connect()	

	database.DB.AutoMigrate(&models.User{})	

}