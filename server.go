package main

import (
		"strings"	
		"fmt"
		"database/sql"
		"os"
		"net/http"
		"regexp"
		"time"
		sqlstruct "fran/sqlstruct"
		"github.com/labstack/echo/v4"
		"github.com/labstack/echo/v4/middleware"
		"github.com/labstack/echo-jwt/v4"
		"github.com/golang-jwt/jwt/v5"
		"golang.org/x/crypto/bcrypt"
		log "github.com/sirupsen/logrus"
		_ "github.com/go-sql-driver/mysql"
)

var err error = nil
var re = regexp.MustCompile(`^[\p{L}0-9]+$`)
var reEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
var db *sql.DB
var jwtSecret = []byte("clave-secreta-123")

func main() {
		log.SetOutput(os.Stdout)
		log.SetLevel(log.DebugLevel)
		dsn := "root:root@tcp(127.0.0.1:3306)/ServicioLoginDB?charset=utf8mb4&parseTime=True&loc=Local"
		db, err = sql.Open("mysql", dsn)
		if err != nil {
				log.Fatalf("Error al abrir conexión: %v", err)
		}
		defer db.Close()

		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(25)
		db.SetConnMaxLifetime(5 * time.Minute)

		if err := db.Ping(); err != nil {
				log.Fatalf("Error al conectar a la base de datos: %v", err)
		}
	
		log.Debugf("Error al abrir la conexion: %v", err)
		e := echo.New()
		
		e.Use(middleware.Logger())		
		e.GET("/usuario/:id", buscarUsuario)
		
		grupoP := e.Group("/p")		
		grupoP.Use(echojwt.JWT([]byte(jwtSecret)))
		grupoP.GET("",filtro)
		grupoP.GET("/usuario", listarUsuarios)
		grupoP.GET("/usuario/:id", buscarUsuario)		
		e.POST("/login", login)		
		e.POST("/registrar", registrar)
		log.Debugf("Fallo al iniciar server: %v", e.Start(":4567"))
}

type Usuario struct {
		Usuario string `json:"usuario" form:"usuario"`
		Contra  string `json:"contra" form:"contra"`
		Email string `json:"email" form:"email"`
		Nombre *string `json:"nombre" form:"nombre"`
		Telefono *string `json:"telefono" form:"telefono"`
		Direccion *string `json:"direccion" form:"direccion"`
}

type UsuarioRol struct {
		Id int `json:"id" form:"id"`
		Usuario string `json:"usuario" form:"usuario"`
		Contra  string `json:"contra" form:"contra"`
		Email string `json:"email" form:"email"`
		Nombre *string `json:"nombre" form:"nombre"`
		Telefono *string `json:"telefono" form:"telefono"`
		Direccion *string `json:"direccion" form:"direccion"`
		Rol *string `json:"rol" form:"rol"`
		Permisos * string `json:"permisos" form:"permisos"`
}

func encriptar(contra string) (string, error){
		bytes_hash, err := bcrypt.GenerateFromPassword([]byte(contra), 15)
		return string(bytes_hash), err
}

func generarJWT(usuario string, rol string, permisos string) (string, error) {
		claims := jwt.MapClaims{
				"usuario": usuario,
				"rol": rol,
				"permisos": permisos,
				"exp":      time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return token.SignedString(jwtSecret)
}


func registrar(c echo.Context) error {
		var u Usuario
		if err := c.Bind(&u); err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "Formulario Incorrecto"})
		}
		if len(u.Usuario) < 5 || !re.MatchString(u.Usuario) || len(u.Contra) < 8 || !re.MatchString(u.Contra) || !reEmail.MatchString(u.Email) {		
				log.Debugf("%v\nApiRes: %v", u, http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "Formulario Incorrecto"})
		}
		u.Contra, err = encriptar(u.Contra)
		if err == nil {		
				if err = alta(u); err != nil{
						log.Errorf("registrar: %v", err)
				}		
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.String(http.StatusOK, u.Usuario + " " + u.Contra + " " +u.Email)
		} else {		
				log.Debugf("%v\nApiRes: %v", u, http.StatusBadRequest)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Hubo un error interno del sistema"})
		}
}

func getUsuario(campo string, valor string) (UsuarioRol, error) {
		query := "SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion, r.nombre AS rol, GROUP_CONCAT(DISTINCT p.nombre ORDER BY p.nombre SEPARATOR ', ') AS permisos FROM Usuario u LEFT JOIN UsuarioRol ur ON u.id = ur.usuario_id LEFT JOIN Rol r ON ur.rol_id = r.id LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id WHERE "+campo+" = ? GROUP BY u.id"
		fmt.Printf("campo: %v valor: %v",campo, valor)
		fila := db.QueryRow(query, valor)
		if fila == nil {
				log.Fatal(fila)
		}
		
		var u UsuarioRol
		if err := sqlstruct.ScanStruct(fila, &u); err != nil {
				log.Fatal(err)
				return u,err
		}
		return u,nil
}


func login(c echo.Context) error{		
		type LoginRequest struct {
				Usuario string `json:"usuario"`
				Contra string `json:"contra"`
		}
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "Formulario Incorrecto"})
		}
		usuario, err := getUsuario("u.usuario", req.Usuario)
		if err != nil{
				return c.JSON(http.StatusNotFound, map[string]string{"error": "Usuario no encontrado"})
		}
		err = bcrypt.CompareHashAndPassword([]byte(usuario.Contra), []byte(req.Contra))
		
		if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "Credenciales incorrectas"})
		}
		
        token, err := generarJWT(usuario.Usuario, *usuario.Rol, *usuario.Permisos)
		
		if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Hubo un error interno del sistema"})
        }
        return c.JSON(http.StatusOK, map[string]string{"token": token, "rol":*usuario.Rol, "permisos":*usuario.Permisos})
}

func filtro(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	usuario := claims["usuario"].(string)
	rol := claims["rol"].(string)
	permisos := claims["permisos"].(string)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Acceso a contenido principal",
		"usuario":    usuario,
		"rol":    rol,
		"permisos":    permisos,
	})
}

func buscarUsuario(c echo.Context) error {
		id := c.Param("id")
		u, err := getUsuario("u.id",id)
		if err == nil {
				log.Errorf("Buscar Usuario: %v",err)
		}
		return c.JSON(http.StatusOK, u)
}

func listarUsuarios(c echo.Context) error {
		limite := c.QueryParam("limite")
		diferencia := c.QueryParam("diferencia")
		if limite == "" {
				limite = "10"
		}
		if diferencia == "" {
				diferencia = "0"
		}
		if err != nil {
				return c.JSON(http.StatusBadRequest, "diferencia debe ser un número")
		}
		
		query := "SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion, r.nombre AS rol, GROUP_CONCAT(DISTINCT p.nombre ORDER BY p.nombre SEPARATOR ', ') AS permisos FROM Usuario u LEFT JOIN UsuarioRol ur ON u.id = ur.usuario_id LEFT JOIN Rol r ON ur.rol_id = r.id LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id GROUP BY u.id LIMIT ? OFFSET ?"
		
		filas, err := db.Query(query,limite,diferencia)
		if err != nil {
				log.Fatal(err)
		}
		var u UsuarioRol
		usuarios := [] any {}
		usuarios, err = sqlstruct.ScanSlice(filas, u)
		if err != nil {
				log.Fatal(err)
		}
		return c.JSON(http.StatusOK, usuarios)
}

func alta(u any) error{
		tabla, campos, valores, err := sqlstruct.StructAstring(u)
		if err != nil {
				log.Fatal(err)
		}
		placeholders := strings.Repeat("?,", len(campos))
		camposStr := strings.Join(campos, ",")
		placeholders = placeholders[:len(placeholders)-1]
	
		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tabla, camposStr, placeholders)
		_, err = db.Exec(query, valores...)
		if(err != nil){		
				log.Errorf("alta: %v",err)
		}
		return err
}
