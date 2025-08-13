package main

import (
	"os"
	"fmt"
	"net/http"
    "regexp"
    "database/sql"
	"reflect"
	"errors"
	"time"
	"strings"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	log "github.com/sirupsen/logrus"
	_ "github.com/go-sql-driver/mysql"
)

var err error = nil
var re = regexp.MustCompile(`^[\p{L}0-9]+$`)
var reEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
var db *sql.DB

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
	Creado string`json:"creado" form:"creado"`
	Ult_mod string `json:"ult_mod" form:"ult_mod"`
	Estado string `json:"estado" form:"estado"`	
    Usuario string `json:"usuario" form:"usuario"`
	Contra  string `json:"contra" form:"contra"`
	Email string `json:"email" form:"email"`
	Nombre *string `json:"nombre" form:"nombre"`
	Telefono *string `json:"telefono" form:"telefono"`
	Direccion *string `json:"direccion" form:"direccion"`
	Rol *string `json:"rol" form:"rol"`
	Permisos * string `json:"permisos" form:"permisos"`
}

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
		log.Fatalf("Error al conectar a MariaDB: %v", err)
	}
	
	log.Debugf("Error al abrir la conexion: %v", err)
	e := echo.New()
	e.POST("/registrar", registrar)
	e.GET("/usuario/:id", buscarUsuario)
	log.Debugf("Fallo al iniciar server: %v", e.Start(":4567"))
}

func encriptar(contra string) (string, error){
	bytes_hash, err := bcrypt.GenerateFromPassword([]byte(contra), 15)
	return string(bytes_hash), err
}

func registrar(c echo.Context) error {
    var u Usuario
	if err := c.Bind(&u); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "Formulario Incorrecto"})
    }
	if len(u.Usuario) < 5 || !re.MatchString(u.Usuario) || len(u.Contra) < 8 || !re.MatchString(u.Contra) || !reEmail.MatchString(u.Email) {		
		log.Debugf("Error: %v\nApiRes: %v", u, http.StatusBadRequest)
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "Formulario Incorrecto"})
	}
	u.Contra, err = encriptar(u.Contra)
	if err == nil {		
		log.Debugf("ApiRes: %v", http.StatusBadRequest)
		
		alta(u)
		return c.String(http.StatusOK, u.Usuario + " " + u.Contra + " " +u.Email)
	} else {		
		log.Debugf("Error: %v\nApiRes: %v", u, http.StatusBadRequest)
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Hubo un error interno del sistema"})
	}
}

func buscarUsuario(c echo.Context) error {
	id := c.Param("id")
	query := "SELECT u.*, r.nombre AS rol, GROUP_CONCAT(DISTINCT p.nombre ORDER BY p.nombre SEPARATOR ', ') AS permisos FROM Usuario u LEFT JOIN UsuarioRol ur ON u.id = ur.usuario_id LEFT JOIN Rol r ON ur.rol_id = r.id LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id WHERE u.id = ? GROUP BY u.id"
	fila := db.QueryRow(query, id)
	if fila == nil {
		log.Fatal(fila)
	}
	var u UsuarioRol
	if err := scanStruct(fila, &u); err != nil {
		log.Fatal(err)
	}

    return c.JSON(http.StatusOK, u)
}

func alta(u any){
	tabla, campos, valores, err := structAstring(u)
	if err != nil {
		log.Fatal(err)
	}
	camposStr := strings.Join(campos, ",")
	placeholders := strings.Repeat("?,", len(campos))
	placeholders = placeholders[:len(placeholders)-1]
	
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tabla, camposStr, placeholders)
	_, err = db.Exec(query, valores...)
	if(err != nil){		
		log.Debugf("Ups %v",err)
	}
}

func structAstring(s any) (tabla string, campos []string, valores []any, error error) {
	t := reflect.TypeOf(s)
	v := reflect.ValueOf(s)
	
	if t.Kind() != reflect.Struct {
		log.Debugf("Error: No es struct")
		return "", nil, nil, errors.New("Debe ser un struct")
	}
	
	tabla = t.Name()
	campos = []string{}
	valores = []any{}
	
	for i := 0; i < t.NumField(); i++ {
		campos = append(campos, strings.ToLower(t.Field(i).Name))
		f := v.Field(i)
		if f.Kind() == reflect.Ptr {
			if f.IsNil() {
				valores = append(valores, nil)
			} else {
				valores = append(valores, f.Elem().Interface())
			}
		} else {
			valores = append(valores, f.Interface())
		}
	}
	return
}


func scanStruct(row *sql.Row, dest any) error {
    v := reflect.ValueOf(dest)
    if v.Kind() != reflect.Ptr || v.IsNil() {
        return errors.New("Error: dest debe ser un struct")
    }
    v = v.Elem()
    if v.Kind() != reflect.Struct {
        return errors.New("Error: dest debe ser un struct")
    }

    campos := make([]any, v.NumField())
    for i := 0; i < v.NumField(); i++ {
        campos[i] = v.Field(i).Addr().Interface()
    }
    return row.Scan(campos...)
}
