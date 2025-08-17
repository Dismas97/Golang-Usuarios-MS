package sqlstruct
import 	(
	"reflect"
	"errors"
	"strings"
    "database/sql"
)
func validarStruct(s any) (reflect.Type, error) {
	t := reflect.TypeOf(s)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, errors.New("tipo debe ser un struct o puntero a struct")
	}

	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).PkgPath != "" {
			return nil, errors.New("campo "+t.Field(i).Name+" no es exportado")
		}
	}
	return t, nil
}

func StructAstring(s any) (tabla string, campos []string, valores []any, error error) {
	t, err := validarStruct(s)
	if err != nil {
		return "", nil, nil, err
	}

	v := reflect.ValueOf(s)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
		
	tabla = t.Name()
	campos = make([]string, t.NumField())
	valores = make([]any, t.NumField())	
	for i := 0; i < t.NumField(); i++ {
		campos[i] = strings.ToLower(t.Field(i).Name)
		f := v.Field(i)
		if f.Kind() == reflect.Ptr {
			if f.IsNil() {
				valores[i] = nil
			} else {
				valores[i] = f.Elem().Interface()
			}
		} else {
			valores[i] = f.Interface()
		}
	}
	return
}

func ScanStruct(row *sql.Row, dest any) error {
    v := reflect.ValueOf(dest)
    if v.Kind() != reflect.Ptr || v.IsNil() {
        return errors.New("dest debe ser un struct")
    }
    v = v.Elem()
    if v.Kind() != reflect.Struct {
        return errors.New("dest debe ser un struct")
    }
    campos := make([]any, v.NumField())
    for i := 0; i < v.NumField(); i++ {
        campos[i] = v.Field(i).Addr().Interface()
    }
    return row.Scan(campos...)
}

func ScanSlice(rows *sql.Rows, tipo any) (retorno []any, err error) {
	t, err := validarStruct(tipo)
	if err != nil {
		return nil, err
	}

	retorno = []any{}
    for rows.Next() {
        ptr := reflect.New(t)      // *T
        elem := ptr.Elem()         // T
        
        campos := make([]any, elem.NumField())
        for i := 0; i < elem.NumField(); i++ {
            campos[i] = elem.Field(i).Addr().Interface() //campos[i]=*T.campoi
        }
		
        if err := rows.Scan(campos...); err != nil {
            return nil, err
        }
        retorno = append(retorno, ptr.Interface())
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }    
    return retorno, nil
}
