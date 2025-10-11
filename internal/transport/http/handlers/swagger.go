package handlers

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// RegisterSwagger registers Swagger UI endpoint on the router.
func RegisterSwagger(r *gin.Engine) {
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}
