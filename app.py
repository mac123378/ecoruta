from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson.errors import InvalidId
import base64
import uuid
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ecoruta2026")

uri = os.environ.get(
    "MONGO_URI",
    "mongodb+srv://dorj090613hmcmdra0_db_user:ecorutamc405@cluster0.dcoib4a.mongodb.net/EcoRuta_405?retryWrites=true&w=majority&appName=Cluster0"
)

client = MongoClient(
    uri,
    tls=True,
    tlsAllowInvalidCertificates=True,
    serverSelectionTimeoutMS=5000
)

db = client["EcoRuta_405"]

unidades_col    = db["unidades"]
operadores_col  = db["operadores"]
quejas_col      = db["quejas"]
comunidades_col = db["comunidades"]
usuarios_col    = db["usuarios"]
admins_col      = db["admins"]
codigos_col     = db["codigos_invitacion"]
horarios_col    = db["horarios"]

OPERADOR_USER = "Operador"
OPERADOR_PASS = "op1234"

DIAS_SEMANA = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"]

def login_requerido(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        if not session.get("logueado"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorador

def solo_admin_operador(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        if session.get("rol") not in ("admin", "operador"):
            flash("No tienes permiso para acceder a esta sección.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorador

def solo_admin(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        if session.get("rol") != "admin":
            flash("Solo el administrador puede acceder a esta sección.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorador

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logueado"):
        return redirect(url_for("index"))

    if request.method == "POST":
        tipo     = request.form.get("tipo")
        usuario  = request.form.get("usuario", "").strip()
        password = request.form.get("password", "").strip()

        # --- ADMIN (verificado desde MongoDB) ---
        if tipo == "admin":
            admin_db = admins_col.find_one({"usuario": usuario})
            if admin_db and admin_db["password"] == password:
                session["logueado"]        = True
                session["usuario"]         = usuario
                session["rol"]             = "admin"
                session["nombre_completo"] = admin_db.get("nombre_completo", usuario)
                flash(f"Bienvenido, {admin_db.get('nombre_completo', usuario)}", "success")
                return redirect(url_for("index"))
            flash("Usuario o contraseña incorrectos.", "error")
            return redirect(url_for("login") + "?tipo=admin")

        # --- REGISTRO DE NUEVO ADMIN CON CÓDIGO ---
        elif tipo == "registro_admin":
            nombre_completo = request.form.get("nombre_completo", "").strip()
            codigo          = request.form.get("codigo", "").strip()
            codigo_doc = codigos_col.find_one({"codigo": codigo, "usado": False})
            if not codigo_doc:
                flash("El código de invitación no es válido o ya fue utilizado.", "error")
                return redirect(url_for("login") + "?tipo=admin&subtipo=registro")
            if admins_col.find_one({"usuario": usuario}):
                flash("Ese nombre de usuario ya está en uso.", "error")
                return redirect(url_for("login") + "?tipo=admin&subtipo=registro")
            admins_col.insert_one({
                "usuario":         usuario,
                "password":        password,
                "nombre_completo": nombre_completo,
                "rol":             "admin"
            })
            codigos_col.update_one(
                {"codigo": codigo},
                {"$set": {"usado": True, "usado_por": usuario}}
            )
            session["logueado"]        = True
            session["usuario"]         = usuario
            session["rol"]             = "admin"
            session["nombre_completo"] = nombre_completo
            flash(f"Cuenta de administrador creada. Bienvenido, {nombre_completo}", "success")
            return redirect(url_for("index"))

        # --- OPERADOR (verificado desde MongoDB) ---
        elif tipo == "operador":
            if usuario == OPERADOR_USER and password == OPERADOR_PASS:
                session["logueado"]        = True
                session["usuario"]         = usuario
                session["rol"]             = "operador"
                session["nombre_completo"] = "Operador"
                flash("Bienvenido, Operador", "success")
                return redirect(url_for("index"))
            flash("Usuario o contraseña incorrectos.", "error")
            return redirect(url_for("login") + "?tipo=operador")

        # --- USUARIO (verificado desde MongoDB) ---
        elif tipo == "usuario":
            nombre_completo = request.form.get("nombre_completo", "").strip()
            existente = usuarios_col.find_one({"usuario": usuario})
            if existente:
                if existente["password"] == password:
                    session["logueado"]        = True
                    session["usuario"]         = usuario
                    session["rol"]             = "usuario"
                    session["nombre_completo"] = existente.get("nombre_completo", usuario)
                    session["comunidad"]       = existente.get("comunidad", "")
                    flash(f"Bienvenido, {existente.get('nombre_completo', usuario)}", "success")
                    return redirect(url_for("index"))
                flash("Contraseña incorrecta.", "error")
                return redirect(url_for("login") + "?tipo=usuario")
            else:
                comunidad_usuario = request.form.get("comunidad", "").strip()
                usuarios_col.insert_one({
                    "usuario":         usuario,
                    "password":        password,
                    "rol":             "usuario",
                    "nombre_completo": nombre_completo,
                    "comunidad":       comunidad_usuario
                })
                session["logueado"]        = True
                session["usuario"]         = usuario
                session["rol"]             = "usuario"
                session["nombre_completo"] = nombre_completo
                session["comunidad"]       = comunidad_usuario
                flash(f"Cuenta creada. Bienvenido, {nombre_completo}", "success")
                return redirect(url_for("index"))

    comunidades = list(comunidades_col.find({}, {"nombre": 1}))
    return render_template("login.html", comunidades=comunidades)


@app.route("/verificar_usuario")
def verificar_usuario():
    usuario = request.args.get("usuario", "").strip()
    existe = usuarios_col.find_one({"usuario": usuario}) is not None
    return jsonify({"existe": existe})


@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for("login"))


@app.route("/codigos_invitacion")
@login_requerido
@solo_admin
def codigos_invitacion():
    codigos = list(codigos_col.find().sort("_id", -1))
    return render_template("codigos_invitacion.html", codigos=codigos)


@app.route("/generar_codigo")
@login_requerido
@solo_admin
def generar_codigo():
    nuevo_codigo = str(uuid.uuid4()).upper()[:12]
    nuevo_codigo = f"{nuevo_codigo[:4]}-{nuevo_codigo[4:8]}-{nuevo_codigo[8:12]}"
    codigos_col.insert_one({
        "codigo":     nuevo_codigo,
        "usado":      False,
        "usado_por":  None,
        "creado_por": session.get("usuario")
    })
    flash(f"Código generado: {nuevo_codigo}", "success")
    return redirect(url_for("codigos_invitacion"))


@app.route("/eliminar_codigo/<id>")
@login_requerido
@solo_admin
def eliminar_codigo(id):
    codigos_col.delete_one({"_id": ObjectId(id)})
    flash("Código eliminado correctamente.", "success")
    return redirect(url_for("codigos_invitacion"))


@app.route("/")
@login_requerido
def index():
    rol = session.get("rol")
    nombre = session.get("nombre_completo", session.get("usuario"))
    return render_template("index.html", rol=rol, nombre_completo=nombre)


@app.route("/ver_rutas")
@login_requerido
def ver_rutas():
    return render_template("ver_rutas.html")


@app.route("/agregar_ruta_form", methods=["GET", "POST"])
@login_requerido
@solo_admin_operador
def agregar_ruta_form():
    if request.method == "POST":
        nueva_ruta = {
            "nombre":    request.form["nombre"],
            "horario":   request.form["horario"],
            "dias":      request.form["dias"],
            "comunidad": request.form["comunidad"]
        }
        comunidades_col.update_one(
            {"nombre": request.form["comunidad"]},
            {"$push": {"rutas": nueva_ruta}}
        )
        flash("Ruta agregada correctamente", "success")
        return redirect(url_for("ver_rutas"))
    return render_template("agregar_ruta_form.html")


@app.route("/guardar_ruta", methods=["POST"])
@login_requerido
@solo_admin_operador
def guardar_ruta():
    datos = request.get_json()
    ruta = {
        "nombre":    datos.get("nombre"),
        "comunidad": datos.get("comunidad"),
        "puntos":    datos.get("puntos")
    }
    db["rutas"].insert_one(ruta)
    return jsonify({"success": True, "mensaje": "Ruta guardada correctamente"})


@app.route("/unidad")
@login_requerido
@solo_admin_operador
def ver_unidad():
    try:
        unidades = list(unidades_col.find())
        rol = session.get("rol")
        return render_template("unidad.html", unidades=unidades, rol=rol)
    except Exception as e:
        return f"Error de conexión con MongoDB: {e}"


@app.route("/agregar_unidad", methods=["GET", "POST"])
@login_requerido
@solo_admin_operador
def agregar_unidad():
    if request.method == "POST":
        nueva_unidad = {
            "numero_unidad":  int(request.form["numero_unidad"]),
            "numero_placa":   request.form["numero_placa"],
            "vigencia_placa": request.form["vigencia_placa"],
            "operador_id":    request.form["operador_id"],
            "comunidad":      request.form["comunidad"],
            "estado":         request.form["estado"]
        }
        unidades_col.insert_one(nueva_unidad)
        flash("Unidad agregada correctamente", "success")
        return redirect(url_for("ver_unidad"))
    return render_template("agregar_unidad.html")


@app.route("/editar_unidad/<id>", methods=["GET", "POST"])
@login_requerido
@solo_admin_operador
def editar_unidad(id):
    unidad = unidades_col.find_one({"_id": ObjectId(id)})
    if request.method == "POST":
        datos_actualizados = {
            "numero_unidad":  int(request.form["numero_unidad"]),
            "numero_placa":   request.form["numero_placa"],
            "vigencia_placa": request.form["vigencia_placa"],
            "operador_id":    request.form["operador_id"],
            "comunidad":      request.form["comunidad"],
            "estado":         request.form["estado"]
        }
        unidades_col.update_one({"_id": ObjectId(id)}, {"$set": datos_actualizados})
        flash("Unidad actualizada correctamente", "success")
        return redirect(url_for("ver_unidad"))
    return render_template("editar_unidad.html", unidad=unidad)


@app.route("/eliminar_unidad/<id>")
@login_requerido
@solo_admin_operador
def eliminar_unidad(id):
    unidades_col.delete_one({"_id": ObjectId(id)})
    flash("Unidad eliminada correctamente", "success")
    return redirect(url_for("ver_unidad"))


@app.route("/buscar_unidad", methods=["GET", "POST"])
@login_requerido
@solo_admin_operador
def buscar_unidad():
    resultados = []
    mensaje = ""
    if request.method == "POST":
        campo = request.form["campo"]
        valor = request.form["valor"].strip()
        if campo == "_id":
            try:
                unidad = unidades_col.find_one({"_id": ObjectId(valor)})
                if unidad:
                    resultados = [unidad]
                else:
                    mensaje = "No se encontró ninguna unidad con ese ID."
            except InvalidId:
                mensaje = "El ID ingresado no es válido."
        else:
            resultados = list(unidades_col.find({campo: {"$regex": valor, "$options": "i"}}))
            if not resultados:
                mensaje = "No se encontraron resultados."
    return render_template("buscar_unidad.html", resultados=resultados, mensaje=mensaje)


@app.route("/agregar_operador", methods=["GET", "POST"])
@login_requerido
@solo_admin_operador
def agregar_operador():
    if request.method == "POST":
        try:
            operador = {
                "nombre":          request.form["nombre"],
                "telefono":        request.form["telefono"],
                "unidad_asignada": request.form["unidad_asignada"],
                "correo":          request.form.get("correo", ""),
                "estatus":         "activo"
            }
            operadores_col.insert_one(operador)
            flash("Operador agregado correctamente", "success")
        except Exception as e:
            flash(f"Error al agregar operador: {e}", "error")
        return redirect(url_for("agregar_operador"))
    return render_template("agregar_operador.html")


@app.route("/ver_operadores")
@login_requerido
@solo_admin_operador
def ver_operadores():
    operadores = list(operadores_col.find())
    return render_template("ver_operadores.html", operadores=operadores)


@app.route("/editar_operador/<id>", methods=["GET", "POST"])
@login_requerido
@solo_admin_operador
def editar_operador(id):
    try:
        operador = operadores_col.find_one({"_id": ObjectId(id)})

        if operador is None:
            flash("Operador no encontrado", "error")
            return redirect(url_for("ver_operadores"))

        if request.method == "POST":
            datos = {
                "nombre": request.form["nombre"],
                "telefono": request.form["telefono"],
                "unidad_asignada": request.form["unidad_asignada"],
                "correo": request.form.get("correo", ""),
                "estatus": request.form["estatus"]
            }

            operadores_col.update_one(
                {"_id": ObjectId(id)},
                {"$set": datos}
            )

            flash("Operador actualizado correctamente", "success")
            return redirect(url_for("ver_operadores"))

        return render_template("editar_operador.html", operador=operador)

    except Exception as e:
        flash(f"Error al editar operador: {e}", "error")
        return redirect(url_for("ver_operadores"))


@app.route("/eliminar_operador/<id>")
@login_requerido
@solo_admin_operador
def eliminar_operador(id):
    try:
        operador = operadores_col.find_one({"_id": ObjectId(id)})

        if operador is None:
            flash("Operador no encontrado.", "error")
        else:
            operadores_col.delete_one({"_id": ObjectId(id)})
            flash("Operador eliminado correctamente.", "success")

    except Exception as e:
        flash(f"Error al eliminar operador: {e}", "error")

    return redirect(url_for("ver_operadores"))


@app.route("/comunidades")
@login_requerido
def ver_comunidades():
    comunidades = list(comunidades_col.find())
    for c in comunidades:
        c["unidades"] = list(unidades_col.find({"comunidad": {"$regex": c["nombre"], "$options": "i"}}))
    rol = session.get("rol")
    return render_template("comunidades.html", comunidades=comunidades, rol=rol)


@app.route("/agregar_comunidad", methods=["POST"])
@login_requerido
@solo_admin_operador
def agregar_comunidad():
    nombre = request.form["nombre"]
    nueva_comunidad = {
        "nombre":     nombre,
        "ubicacion":  request.form["ubicacion"],
        "habitantes": int(request.form["habitantes"]),
        "tipo":       request.form["tipo"],
        "rutas":      []
    }
    comunidades_col.insert_one(nueva_comunidad)
    flash("Comunidad agregada correctamente", "success")
    return redirect(url_for("ver_comunidades"))


@app.route("/ver_comunidades_lista")
@login_requerido
def ver_comunidades_lista():
    comunidades = list(comunidades_col.find())
    for c in comunidades:
        c["unidades"] = list(unidades_col.find({"comunidad": {"$regex": c["nombre"], "$options": "i"}}))
    rol = session.get("rol")
    return render_template("lista_comunidades.html", comunidades=comunidades, rol=rol)


@app.route("/editar_comunidad/<id>", methods=["GET", "POST"])
@login_requerido
@solo_admin_operador
def editar_comunidad(id):

    comunidad = comunidades_col.find_one({"_id": ObjectId(id)})

    if comunidad is None:
        flash("La comunidad no existe.", "error")
        return redirect(url_for("ver_comunidades_lista"))

    if request.method == "POST":

        datos_actualizados = {
            "nombre": request.form["nombre"],
            "ubicacion": request.form["ubicacion"],
            "habitantes": int(request.form["habitantes"]),
            "tipo": request.form["tipo"]
        }

        comunidades_col.update_one(
            {"_id": ObjectId(id)},
            {"$set": datos_actualizados}
        )

        flash("Comunidad actualizada correctamente.", "success")
        return redirect(url_for("ver_comunidades_lista"))

    return render_template(
        "editar_comunidad.html",
        comunidad=comunidad
    )


@app.route("/eliminar_comunidad/<id>")
@login_requerido
@solo_admin_operador
def eliminar_comunidad(id):

    comunidad = comunidades_col.find_one({"_id": ObjectId(id)})

    if comunidad is None:
        flash("La comunidad no existe.", "error")
        return redirect(url_for("ver_comunidades_lista"))

    comunidades_col.delete_one({"_id": ObjectId(id)})

    flash("Comunidad eliminada correctamente.", "success")

    return redirect(url_for("ver_comunidades_lista"))

@app.route("/agregar_ruta/<comunidad_id>", methods=["POST"])
@login_requerido
@solo_admin_operador
def agregar_ruta(comunidad_id):
    nueva_ruta = {
        "nombre":  request.form["nombre_ruta"],
        "horario": request.form["horario"],
        "dias":    request.form["dias"]
    }
    comunidades_col.update_one({"_id": ObjectId(comunidad_id)}, {"$push": {"rutas": nueva_ruta}})
    flash("Ruta agregada correctamente", "success")
    return redirect(url_for("ver_comunidades_lista"))


@app.route("/enviar_queja", methods=["GET", "POST"])
@login_requerido
def enviar_queja():
    rol = session.get("rol")
    if rol in ("admin", "operador"):
        return redirect(url_for("ver_quejas"))
    if request.method == "POST":
        foto_base64 = None
        if "foto" in request.files:
            foto = request.files["foto"]
            if foto and foto.filename != "":
                foto_data = foto.read()
                foto_base64 = base64.b64encode(foto_data).decode("utf-8")
                foto_base64 = f"data:{foto.content_type};base64,{foto_base64}"
        nueva_queja = {
            "usuario":         session.get("usuario"),
            "nombre_completo": session.get("nombre_completo", session.get("usuario")),
            "colonia":         request.form["colonia"],
            "fecha_hora":      request.form["fecha_hora"],
            "descripcion":     request.form["descripcion"],
            "estado":          "pendiente",
            "foto":            foto_base64
        }
        quejas_col.insert_one(nueva_queja)
        flash("Queja enviada correctamente", "success")
        return redirect(url_for("ver_quejas"))
    return render_template("quejas.html", rol=rol)


@app.route("/ver_quejas")
@login_requerido
def ver_quejas():
    quejas = list(quejas_col.find())
    rol = session.get("rol")
    return render_template("ver_quejas.html", quejas=quejas, rol=rol)


@app.route("/cambiar_estado_queja/<id>/<estado>")
@login_requerido
@solo_admin_operador
def cambiar_estado_queja(id, estado):

    estados_validos = ["recibido", "pendiente", "atendido"]

    if estado in estados_validos:
        quejas_col.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"estado": estado}}
        )
        flash(f"Estado de la queja actualizado a: {estado}", "success")

    return redirect(url_for("ver_quejas"))


@app.route("/eliminar_queja/<id>")
@login_requerido
@solo_admin_operador
def eliminar_queja(id):

    try:
        quejas_col.delete_one({"_id": ObjectId(id)})
        flash("Queja eliminada correctamente.", "success")

    except Exception as e:
        flash(f"Error al eliminar la queja: {e}", "error")

    return redirect(url_for("ver_quejas"))


@app.route("/api/generar_rutas")
@login_requerido
def generar_rutas():
    comunidades = list(comunidades_col.find())
    rutas = []
    base_lat = 19.823
    base_lng = -100.416
    offset = 0.01
    for i, c in enumerate(comunidades):
        ruta = {
            "comunidad": c["nombre"],
            "horario":   c.get("horario", "08:00"),
            "puntos": [
                {"lat": base_lat + (i * offset),         "lng": base_lng + (i * offset)},
                {"lat": base_lat + (i * offset) + 0.005, "lng": base_lng + (i * offset) + 0.005}
            ]
        }
        rutas.append(ruta)
    return jsonify(rutas)


@app.route("/editar_ruta/<comunidad_id>/<ruta_index>", methods=["POST"])
@login_requerido
@solo_admin_operador
def editar_ruta(comunidad_id, ruta_index):
    comunidad = comunidades_col.find_one({"_id": ObjectId(comunidad_id)})
    rutas = comunidad.get("rutas", [])
    if 0 <= int(ruta_index) < len(rutas):
        rutas[int(ruta_index)]["nombre"]  = request.form["nombre_ruta"]
        rutas[int(ruta_index)]["horario"] = request.form["horario"]
        rutas[int(ruta_index)]["dias"]    = request.form["dias"]
        comunidades_col.update_one({"_id": ObjectId(comunidad_id)}, {"$set": {"rutas": rutas}})
        flash("Horario actualizado correctamente", "success")
    return redirect(url_for("ver_comunidades_lista"))


# --- MÓDULO DE HORARIOS ---

@app.route("/horarios")
@login_requerido
def ver_horarios():
    horarios = list(horarios_col.find())
    orden = {dia: i for i, dia in enumerate(DIAS_SEMANA)}
    horarios.sort(key=lambda h: (orden.get(h.get("dia", ""), 99), h.get("hora", "")))
    rol = session.get("rol")
    return render_template("horarios.html", horarios=horarios, rol=rol, dias_semana=DIAS_SEMANA)


@app.route("/agregar_horario", methods=["GET", "POST"])
@login_requerido
@solo_admin
def agregar_horario():
    if request.method == "POST":
        nuevo_horario = {
            "dia":       request.form["dia"],
            "hora":      request.form["hora"],
            "comunidad": request.form["comunidad"]
        }
        horarios_col.insert_one(nuevo_horario)
        flash("Horario agregado correctamente", "success")
        return redirect(url_for("ver_horarios"))
    comunidades = list(comunidades_col.find({}, {"nombre": 1}))
    return render_template("agregar_horario.html", comunidades=comunidades, dias_semana=DIAS_SEMANA)


@app.route("/editar_horario/<id>", methods=["GET", "POST"])
@login_requerido
@solo_admin
def editar_horario(id):
    horario = horarios_col.find_one({"_id": ObjectId(id)})
    if horario is None:
        flash("Horario no encontrado", "error")
        return redirect(url_for("ver_horarios"))
    if request.method == "POST":
        datos_actualizados = {
            "dia":       request.form["dia"],
            "hora":      request.form["hora"],
            "comunidad": request.form["comunidad"]
        }
        horarios_col.update_one({"_id": ObjectId(id)}, {"$set": datos_actualizados})
        flash("Horario actualizado correctamente", "success")
        return redirect(url_for("ver_horarios"))
    comunidades = list(comunidades_col.find({}, {"nombre": 1}))
    return render_template("editar_horario.html", horario=horario, comunidades=comunidades, dias_semana=DIAS_SEMANA)


@app.route("/eliminar_horario/<id>")
@login_requerido
@solo_admin
def eliminar_horario(id):
    horarios_col.delete_one({"_id": ObjectId(id)})
    flash("Horario eliminado correctamente", "success")
    return redirect(url_for("ver_horarios"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
