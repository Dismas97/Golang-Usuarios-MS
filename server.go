package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"fran/controles"
	"fran/utils"
	"io"
	"os"
	"time"
	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Config struct {
		ServerPort int `json:"server_port"`
		DBPort int `json:"db_port"`
		DB string `json:"db"`
		MaxCon int `json:"max_con"`
		DBUsuario string `json:"db_usuario"`
		DBContra string `json:"db_contra"`
		JWTSecret string `json:"jwt_secret"`
}
var err error = nil

func main() {

		logRotator := &lumberjack.Logger{
				Filename:   "logs.log",
				MaxSize:    10,         //MB
				MaxBackups: 3,
				MaxAge:     28,         // Días
				Compress:   true,
		}
		
		multiWriter := io.MultiWriter(os.Stdout, logRotator)
		log.SetOutput(multiWriter)
		log.SetLevel(log.DebugLevel)
		
		file, _ := os.Open("config.json")
		defer file.Close()

		var config Config
		decoder := json.NewDecoder(file)
		_ = decoder.Decode(&config)

		log.Debug(config)
		dsn := fmt.Sprintf("%s:%s@tcp(127.0.0.1:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",config.DBUsuario, config.DBContra, config.DBPort, config.DB)

		utils.JWTSecret = []byte(config.JWTSecret)
		utils.BD, err = sql.Open("mysql", dsn)
		if err != nil {
				log.Fatalf("Error al abrir conexión: %v", err)
		}
		defer utils.BD.Close()

		utils.BD.SetMaxOpenConns(config.MaxCon)
		utils.BD.SetMaxIdleConns(config.MaxCon)
		utils.BD.SetConnMaxLifetime(5 * time.Minute)

		if err := utils.BD.Ping(); err != nil {
				log.Fatalf("Conexion BD: %v", err)
		}
		
		e := echo.New()
		e.Use(middleware.Logger())
		
		e.POST("/login", controles.Login)
		e.POST("/registrar", controles.Registrar)
		e.GET("",controles.FiltroCheck)
		
		grupoP := e.Group("/p")
		grupoP.Use(echojwt.JWT(utils.JWTSecret))
		grupoP.Use(controles.FiltroSuperAdmin)
		grupoP.GET("", controles.FiltroCheck)
		grupoP.GET("/usuario", controles.ListarUsuarios)
		grupoP.GET("/usuario/:id", controles.BuscarUsuario)
		grupoP.DELETE("/usuario/:id", controles.BajaUsuario)
		grupoP.PUT("/usuario/:id", controles.ModificarUsuario)
		grupoP.DELETE("/usuario/:id/rol", controles.BajaUsuarioRol)
		grupoP.POST("/usuario/:id/rol", controles.AltaUsuarioRol)
		grupoP.POST("/permiso", controles.AltaRolOPermiso)
		grupoP.POST("/rol", controles.AltaRolOPermiso)
		grupoP.GET("/rol", controles.ListarRoles)
		grupoP.POST("/rol/:id", controles.AltaRolPermiso)
		grupoP.GET("/rol/:id", controles.BuscarRol)
		grupoP.DELETE("/rol/:id", controles.BajaRolPermiso)
		
		log.Errorf("Server: %v", e.Start(fmt.Sprintf(":%d",config.ServerPort)))
}
