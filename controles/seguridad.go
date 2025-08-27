package controles

import (
		"encoding/json"
		"fran/sqlstruct"
		"fran/utils"
		"net/http"
		"strconv"
		"time"

		_ "github.com/go-sql-driver/mysql"
		"github.com/golang-jwt/jwt/v5"
		"github.com/labstack/echo/v4"
		log "github.com/sirupsen/logrus"
		"golang.org/x/crypto/bcrypt"
)

type Sesion struct {
		Id int `json:"id" form:"id"` 
		Usuario_id int `json:"usuario_id" form:"usuario_id"`
		Refresh_token string `json:"refresh_token" form:"refresh_token"`
		Creado time.Time `json:"creado" form:"creado"`
		Expira time.Time `json:"expira" form:"expira"`
		Activo bool `json:"activo" form:"activo"`
}

func diferenciaFechas(fecha1, fecha2 time.Time) (dias, horas float64) {
		diferencia := fecha2.Sub(fecha1)
		horas = diferencia.Hours()
		dias = horas / 24
		return dias, horas
}

func desactivarSesion(usuario_id int, refresh_token string) error {
		query := "UPDATE Sesion SET activo = false WHERE usuario_id = ? AND refresh_token = ?"
		_, err := utils.BD.Exec(query, usuario_id, refresh_token)
		if err != nil {
				log.Errorf("Error al desactivar sesión: %v", err)
				return err
		}
		return nil
}

func encriptar(contra string) (string, error){
		bytes_hash, err := bcrypt.GenerateFromPassword([]byte(contra), 15)
		return string(bytes_hash), err
}

func getSesion(usuario_id int, refresh_token string) (res Sesion, err error) {
		log.Debugf("usuario: %d, token: %s", usuario_id, refresh_token)
		query := "SELECT * FROM Sesion WHERE usuario_id = ? AND refresh_token = ?"
		fila := utils.BD.QueryRow(query, usuario_id, refresh_token)
		
		if err := sqlstruct.ScanStruct(fila, &res); err != nil  {
				log.Errorf("%v",err)
				return res, err
		}
		return res, nil
}

func generarJWTAcceso(usuario UsuarioDetallado) (access string, err error) {
		accclaims := jwt.MapClaims{
				"usuario": usuario.Id,
				"tipo": "access",
				"rol": *usuario.Rol,
				"permisos": *usuario.Permisos,
				"exp": time.Now().Add(15 * time.Minute).Unix(),
		}
		at := jwt.NewWithClaims(jwt.SigningMethodHS256, accclaims)
		access, err = at.SignedString(utils.JWTSecret)
		return
}

func generarJWT(usuario UsuarioDetallado) (access string, refresh string, err error) {
		access, err = generarJWTAcceso(usuario)
		refreshClaims := jwt.MapClaims{
				"usuario": usuario.Id,
				"tipo": "refresh",
				"exp": time.Now().Add(7 * 24 * time.Hour).Unix(),
		}
		rt := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
		refresh, err = rt.SignedString(utils.JWTSecret)
		aux := Sesion{
				Usuario_id : usuario.Id,
				Refresh_token : refresh,
				Creado : time.Now(),
				Expira : time.Now().AddDate(0,0,7),
				Activo : true,
		}
		sqlstruct.Alta(aux)
		return
}

func RefreshToken(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		tipo := claims["tipo"].(string)
		if tipo != "refresh" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"mensaje":utils.MsjResErrCredInvalidas})
		}
		refresh := user.Raw
		usuario_id := int(claims["usuario"].(float64))
		sesion, err := getSesion(usuario_id, refresh)
		
		if err != nil || !sesion.Activo || time.Now().After(sesion.Expira){
				if sesion.Activo && time.Now().After(sesion.Expira) {
						desactivarSesion(sesion.Usuario_id, sesion.Refresh_token)
				}
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusNotFound)
				return c.JSON(http.StatusNotFound, map[string]string{"mensaje":utils.MsjResErrCredInvalidas})
		}	
		
		usuario, err := getUsuario("u.id", strconv.Itoa(usuario_id) )
		
		if err != nil{
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusNotFound)
				return c.JSON(http.StatusNotFound, map[string]string{"mensaje":utils.MsjResErrCredInvalidas})
		}

		dias, horas := diferenciaFechas(time.Now(), sesion.Expira)
		log.Debugf("Faltan %.2f horas y %.2f dias para que expire el token", horas, dias)
		refrescar := dias < 1
		var access string
		var aux []RolOPermiso
		if refrescar {				
				log.Debug("Generando nuevo refresh token..")
				if err := desactivarSesion(sesion.Usuario_id, sesion.Refresh_token); err != nil {
						log.Error(err)
						return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
				}
				access, refresh, err = generarJWT(usuario)
				if err != nil {				
						log.Error(err)
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
				}
		} else {				
				log.Debug("Generando nuevo access token, refresh igual..")
				access, err = generarJWTAcceso(usuario)
				if err != nil {
						log.Error(err)
						return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje": utils.MsjResErrInterno})
				}
		}
		err = json.Unmarshal([]byte(*usuario.Permisos),&aux)
		if err != nil {				
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
		log.Debugf("ApiRes: %v", http.StatusOK)
		return c.JSON(http.StatusOK, map[string]any{"access_token": access, "refresh_token": refresh, "rol":*usuario.Rol, "permisos": aux})
}

func FiltroCheck(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		usuario := claims["usuario"].(string)
		rol := claims["rol"].(string)
		permisos := claims["permisos"].(string)

		return c.JSON(http.StatusOK, map[string]string{
				"mensaje": "Filtro Check",
				"usuario": usuario,
				"rol": rol,
				"permisos": permisos,
		})
}

func FiltroSuperAdmin(next echo.HandlerFunc) echo.HandlerFunc {
		return func (c echo.Context) error {
				user := c.Get("user").(*jwt.Token)
				claims := user.Claims.(jwt.MapClaims)
				tipo := claims["tipo"].(string)
				if tipo != "access" {
						return c.JSON(http.StatusUnauthorized, map[string]string{"mensaje":utils.MsjResErrCredInvalidas})
				}	
				rol := claims["rol"].(string)
				if rol != "ADMIN" {
						return c.JSON(http.StatusUnauthorized, map[string]string{"mensaje":utils.MsjResErrNoAutorizado})
				}		
				return next(c)
		}
}
