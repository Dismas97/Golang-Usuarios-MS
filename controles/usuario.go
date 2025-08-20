package controles

import (
		"encoding/json"
		"errors"
		"fran/sqlstruct"
		"fran/utils"
		"net/http"
		"time"
		_ "github.com/go-sql-driver/mysql"
		"github.com/golang-jwt/jwt/v5"
		"github.com/labstack/echo/v4"
		log "github.com/sirupsen/logrus"
		"golang.org/x/crypto/bcrypt"
)

var err error = nil

type Usuario struct {
		Usuario string `json:"usuario" form:"usuario"`
		Contra  string `json:"contra" form:"contra"`
		Email string `json:"email" form:"email"`
		Nombre *string `json:"nombre" form:"nombre"`
		Telefono *string `json:"telefono" form:"telefono"`
		Direccion *string `json:"direccion" form:"direccion"`
}

type UsuarioDetallado struct {
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

type UsuarioDetalladoRes struct {
		Id int `json:"id" form:"id"`
		Usuario string `json:"usuario" form:"usuario"`
		Contra  string `json:"contra" form:"contra"`
		Email string `json:"email" form:"email"`
		Nombre *string `json:"nombre" form:"nombre"`
		Telefono *string `json:"telefono" form:"telefono"`
		Direccion *string `json:"direccion" form:"direccion"`
		Rol *string `json:"rol" form:"rol"`
		Permisos []RolOPermiso `json:"permisos" form:"permisos"`
}

type LoginRequest struct {
		Usuario string `json:"usuario"`
		Contra string `json:"contra"`
}

func chequeoQueryData(fuente map[string]any, campos []string) error {
		for i := range campos {
				log.Debug(fuente[campos[i]])
				if fuente[campos[i]] == nil || fuente[campos[i]] == ""{
						return errors.New("campo "+campos[i]+" no exportado")
				}
		}		
		return nil
}

func getUsuario(campo string, valor string) (UsuarioDetallado, error) {
		log.Debugf("getUsuario(%v,%v)", campo, valor)
		query := "SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion, r.nombre AS rol, JSON_ARRAYAGG(JSON_OBJECT('id', p.id,'nombre', p.nombre)) AS permisos FROM Usuario u LEFT JOIN UsuarioRol ur ON u.id = ur.usuario_id LEFT JOIN Rol r ON ur.rol_id = r.id LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id WHERE "+campo+" = ? GROUP BY u.id"
		fila := utils.BD.QueryRow(query, valor)
		
		var u UsuarioDetallado
		if err := sqlstruct.ScanStruct(fila, &u); err != nil {
				log.Error(err)
				return u,err
		}
		return u,nil
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
		return token.SignedString(utils.JWTSecret)

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
				rol := claims["rol"].(string)
				if rol != "ADMIN" {
						return c.JSON(http.StatusUnauthorized, map[string]string{"mensaje":utils.MsjResErrNoAutorizado})
				}		
				return next(c)
		}
}

func Registrar(c echo.Context) error {
		var u Usuario
		log.Debug("registrar")
		if  err := c.Bind(&u); err != nil || len(u.Usuario) < 5 || !utils.REAlfaNum.MatchString(u.Usuario) || len(u.Contra) < 8 || !utils.REAlfaNum.MatchString(u.Contra) || !utils.REEmail.MatchString(u.Email) {		
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}
		
		u.Contra, err = encriptar(u.Contra)
		if err == nil {
				if _,err = sqlstruct.Alta(u); err != nil{
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
				}
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.JSON(http.StatusOK, map[string]string{"mensaje":utils.MsjResAltaExito})
		} else {		
				log.Debugf("%v\nApiRes: %v", u, http.StatusBadRequest)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
}

func Login(c echo.Context) error{
		log.Debug("login")
		var req LoginRequest
		if err := c.Bind(&req); err != nil {				
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}
		usuario, err := getUsuario("u.usuario", req.Usuario)
		if err != nil{
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusNotFound)
				return c.JSON(http.StatusNotFound, map[string]string{"mensaje":utils.MsjResErrUsrNoExiste})
		}
		err = bcrypt.CompareHashAndPassword([]byte(usuario.Contra), []byte(req.Contra))
		
		if err != nil {				
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrCredInvalidas})
		}
		
        token, err := generarJWT(usuario.Usuario, *usuario.Rol, *usuario.Permisos)
		
		var aux []RolOPermiso
		err = json.Unmarshal([]byte(*usuario.Permisos),&aux)
		if err != nil {				
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
        }
		log.Debugf("ApiRes: %v", http.StatusOK)
        return c.JSON(http.StatusOK, map[string]any{"token": token, "rol":*usuario.Rol, "permisos": aux})
}

func AltaUsuarioRol(c echo.Context) error {
		var aux map[string]any
		id := c.Param("id")
		c.Bind(&aux)
		if err = chequeoQueryData(aux,  []string{"rol_id"}); err != nil{				
				log.Debugf("%s\nApiRes: %v", err, http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}

		query := "INSERT INTO UsuarioRol (usuario_id,rol_id) VALUES (?, ?)"
		_, err := utils.BD.Exec(query, id, aux["rol_id"])
		if(err != nil){
				log.Errorf("AltaUsuarioRol: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno} )
		}		
		return c.JSON(http.StatusOK, map[string]string{"mensaje":utils.MsjResModExito})		
}

func BajaUsuarioRol(c echo.Context) error {
		var aux map[string]any
		id := c.Param("id")
		c.Bind(&aux)
		if err = chequeoQueryData(aux,  []string{"rol_id"}); err != nil{				
				log.Debugf("%s\nApiRes: %v", err, http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}

		query := "DELETE FROM UsuarioRol WHERE usuario_id = ? AND rol_id = ?"
		_, err := utils.BD.Exec(query, id, aux["rol_id"])
		if(err != nil){
				log.Errorf("BajaUsuarioRol: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno} )
		}		
		return c.JSON(http.StatusOK, map[string]string{"mensaje":utils.MsjResBajaExito})		
}

func BuscarUsuario(c echo.Context) error {
		id := c.Param("id")
		u, err := getUsuario("u.id",id)
		if err != nil {
				log.Errorf("buscarUsuario: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno} )
		}
		var aux []RolOPermiso
		err = json.Unmarshal([]byte(*u.Permisos),&aux)
		res := UsuarioDetalladoRes{
				Id: u.Id,
				Usuario: u.Usuario,
				Contra: u.Contra,
				Direccion: u.Direccion,
				Rol: u.Rol,
				Permisos: aux,
        }
		return c.JSON(http.StatusOK,
				map[string]any{
						"mensaje":utils.MsjResExito,
						"datos":res})
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
		
		query := "SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion, r.nombre AS rol, JSON_ARRAYAGG(JSON_OBJECT('id', p.id,'nombre', p.nombre)) AS permisos FROM Usuario u LEFT JOIN UsuarioRol ur ON u.id = ur.usuario_id LEFT JOIN Rol r ON ur.rol_id = r.id LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id GROUP BY u.id LIMIT ? OFFSET ?"
		
		filas, err := utils.BD.Query(query,limite,diferencia)
		var u UsuarioDetallado
		usuarios := [] any {}
		usuarios, err = sqlstruct.ScanSlice(filas, u)
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}

		var res []UsuarioDetalladoRes
		
		var auxPermisos []RolOPermiso
		for i := range usuarios {
				auxPuntero := usuarios[i].(*UsuarioDetallado)
				auxUsuario := *auxPuntero
				auxPermisos = nil
				err := json.Unmarshal([]byte(*auxUsuario.Permisos), &auxPermisos)
				if err != nil {
						log.Errorf("ListarUsuarios: %v",err)
						return c.JSON(http.StatusInternalServerError, 
								map[string]string{"msj": utils.MsjResErrInterno})
				}
				resindex := UsuarioDetalladoRes{
						Id: auxUsuario.Id,
						Usuario: auxUsuario.Usuario,
						Contra: auxUsuario.Contra,
						Direccion: auxUsuario.Direccion,
						Rol: auxUsuario.Rol,
						Permisos: auxPermisos,
				}
				res = append(res,resindex)
		}
		
		return c.JSON(http.StatusOK,
				map[string]any{
						"mensaje":utils.MsjResExito,
						"datos":res})
}

func ModificarUsuario(c echo.Context) error {		
		var u Usuario
		log.Debug("ModificarUsuario")
		id := c.Param("id")
		if  err := c.Bind(&u); err != nil || len(u.Usuario) < 5 || !utils.REAlfaNum.MatchString(u.Usuario) || len(u.Contra) < 8 || !utils.REAlfaNum.MatchString(u.Contra) || !utils.REEmail.MatchString(u.Email) {		
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}
		
		u.Contra, err = encriptar(u.Contra)
		if err == nil {		
				if err = sqlstruct.Modificar(u,id); err != nil{
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
				}
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.JSON(http.StatusOK, map[string]string{"mensaje": utils.MsjResModExito})
		} else {		
				log.Debugf("%v\nApiRes: %v", u, http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
}

func BajaUsuario(c echo.Context) error {
		log.Debug("BajaUsuario")
		id := c.Param("id")
		
		if err = sqlstruct.Baja("Usuario", id); err == nil {
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.JSON(http.StatusOK, map[string]string{"mensaje": utils.MsjResBajaExito})
		} else {		
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
}
