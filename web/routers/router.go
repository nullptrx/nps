package routers

import (
	"net/http"

	"github.com/beego/beego"
	"github.com/djylb/nps/web/controllers"
)

func Init() {
	// Handle 404
	beego.ErrorHandler("404", func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	})

	web_base_url := beego.AppConfig.String("web_base_url")
	if len(web_base_url) > 0 {
		ns := beego.NewNamespace(web_base_url,
			beego.NSRouter("/", &controllers.IndexController{}, "*:Index"),
			beego.NSAutoRouter(&controllers.IndexController{}),
			beego.NSAutoRouter(&controllers.LoginController{}),
			beego.NSAutoRouter(&controllers.ClientController{}),
			beego.NSAutoRouter(&controllers.AuthController{}),
			beego.NSAutoRouter(&controllers.GlobalController{}),
		)
		beego.AddNamespace(ns)
	} else {
		beego.Router("/", &controllers.IndexController{}, "*:Index")
		beego.AutoRouter(&controllers.IndexController{})
		beego.AutoRouter(&controllers.LoginController{})
		beego.AutoRouter(&controllers.ClientController{})
		beego.AutoRouter(&controllers.AuthController{})
		beego.AutoRouter(&controllers.GlobalController{})

	}
}
