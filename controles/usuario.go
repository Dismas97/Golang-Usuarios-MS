package controles

import (
		"strings"	
		"fmt"
		"net/http"
		"fran/sqlstruct"
		"fran/utils"
		"github.com/labstack/echo/v4"
		"github.com/golang-jwt/jwt/v5"
		"time"
		"golang.org/x/crypto/bcrypt"
		log "github.com/sirupsen/logrus"
		_ "github.com/go-sql-driver/mysql"
)

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
const (
		MsjResErrInterno = "Error interno en el sistema"
		MsjResErrFormIncorrecto = "Formulario incorrecto"
		MsjResErrUsrNoExiste = "Usuario no encontrado"
		MsjResErrCredInvalidas ="Credenciales invalidas"		
		MsjResErrNoAutorizado ="No autorizado"
)

var err error = nil

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
		return token.SignedString(utils.JWTSecret)

}

func FiltroSuperAdmin(next echo.HandlerFunc) echo.HandlerFunc {
		return func (c echo.Context) error {
				user := c.Get("user").(*jwt.Token)
				claims := user.Claims.(jwt.MapClaims)
				rol := claims["rol"].(string)
				if rol != "ADMIN" {
						return c.JSON(http.StatusUnauthorized, map[string]string{"mensaje":MsjResErrNoAutorizado})
				}		
				return next(c)
		}
}

func Registrar(c echo.Context) error {
		var u Usuario
		log.Debug("registrar")
		if  err := c.Bind(&u); err != nil || len(u.Usuario) < 5 || !utils.REAlfaNum.MatchString(u.Usuario) || len(u.Contra) < 8 || !utils.REAlfaNum.MatchString(u.Contra) || !utils.REEmail.MatchString(u.Email) {		
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":MsjResErrFormIncorrecto})
		}
		
		u.Contra, err = encriptar(u.Contra)
		if err == nil {		
				if err = alta(u); err != nil{
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":MsjResErrInterno})
				}
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.JSON(http.StatusOK, map[string]string{"mensaje": "Registro Exitoso"})
		} else {		
				log.Debugf("%v\nApiRes: %v", u, http.StatusBadRequest)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":MsjResErrInterno})
		}
}

func Login(c echo.Context) error{		
		type LoginRequest struct {
				Usuario string `json:"usuario"`
				Contra string `json:"contra"`
		}
		log.Debug("login")
		var req LoginRequest
		if err := c.Bind(&req); err != nil {				
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":MsjResErrFormIncorrecto})
		}
		usuario, err := getUsuario("u.usuario", req.Usuario)
		if err != nil{
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusNotFound)
				return c.JSON(http.StatusNotFound, map[string]string{"mensaje":MsjResErrUsrNoExiste})
		}
		err = bcrypt.CompareHashAndPassword([]byte(usuario.Contra), []byte(req.Contra))
		
		if err != nil {				
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":MsjResErrCredInvalidas})
		}
		
        token, err := generarJWT(usuario.Usuario, *usuario.Rol, *usuario.Permisos)
		
		if err != nil {				
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje": MsjResErrInterno})
        }
		log.Debugf("ApiRes: %v", http.StatusOK)
        return c.JSON(http.StatusOK, map[string]string{"token": token, "rol":*usuario.Rol, "permisos":*usuario.Permisos})
}

func FiltroCheck(c echo.Context) error {
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

func BuscarUsuario(c echo.Context) error {
		id := c.Param("id")
		u, err := getUsuario("u.id",id)
		if err != nil {
				log.Errorf("buscarUsuario: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error":MsjResErrInterno} )
		}
		return c.JSON(http.StatusOK, u)
}

func ListarUsuarios(c echo.Context) error {
		limite := c.QueryParam("limite")
		diferencia := c.QueryParam("diferencia")
		log.Debugf("listarUsuarios: limite %v diferencia %v", limite, diferencia)
		if limite == "" {
				limite = "10"
		}
		if diferencia == "" {
				diferencia = "0"
		}
		
		query := "SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion, r.nombre AS rol, GROUP_CONCAT(DISTINCT p.nombre ORDER BY p.nombre SEPARATOR ', ') AS permisos FROM Usuario u LEFT JOIN UsuarioRol ur ON u.id = ur.usuario_id LEFT JOIN Rol r ON ur.rol_id = r.id LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id GROUP BY u.id LIMIT ? OFFSET ?"
		
		filas, err := utils.BD.Query(query,limite,diferencia)
		var u UsuarioRol
		usuarios := [] any {}
		usuarios, err = sqlstruct.ScanSlice(filas, u)
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":MsjResErrInterno})
		}
		return c.JSON(http.StatusOK, usuarios)
}

func alta(u any) error{
		log.Debugf("alta: %v", u)
		tabla, campos, valores, err := sqlstruct.StructAstring(u)
		if err != nil {
				log.Error(err)
				return err
		}
		placeholders := strings.Repeat("?,", len(campos))
		camposStr := strings.Join(campos, ",")
		placeholders = placeholders[:len(placeholders)-1]
	
		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tabla, camposStr, placeholders)
		_, err = utils.BD.Exec(query, valores...)
		if(err != nil){
				log.Error(err)
				return err
		}
		return nil
}

func getUsuario(campo string, valor string) (UsuarioRol, error) {
		log.Debugf("getUsuario(%v,%v)", campo, valor)
		query := "SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion, r.nombre AS rol, GROUP_CONCAT(DISTINCT p.nombre ORDER BY p.nombre SEPARATOR ', ') AS permisos FROM Usuario u LEFT JOIN UsuarioRol ur ON u.id = ur.usuario_id LEFT JOIN Rol r ON ur.rol_id = r.id LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id WHERE "+campo+" = ? GROUP BY u.id"
		fila := utils.BD.QueryRow(query, valor)
		
		var u UsuarioRol
		if err := sqlstruct.ScanStruct(fila, &u); err != nil {
				log.Error(err)
				return u,err
		}
		return u,nil
}
