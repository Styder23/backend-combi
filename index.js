require("dotenv").config(); // Carga las variables de entorno
const express = require("express");
const db = require("./db.js");
const bodyParser = require("body-parser");
const cors = require("cors");
const moment = require("moment-timezone");
const app = express();
// const PORT = process.env.PORT || 8080; // Puerto para el servidor
const cron = require("node-cron");
const { PORT } = require("./server.js");
const uploadRouters = require("./routes/uploadRoutes.js");
const bcrypt = require('bcrypt');
const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");
// Middleware
app.use(cors({
  origin: "*", // Permitir todas las solicitudes de origen
  methods: ["GET", "POST", "PUT", "DELETE"],
}));
app.use(bodyParser.json());
app.use("/api", uploadRouters);

// RUTAS PARA SUBIR LAS IMAGENES
app.use(express.json());

// 🔹 Usar las rutas de subida de imágenes
app.use("/api", uploadRouters);

// Servir las imágenes estáticamente
app.use('/incidenteupload', express.static('incidenteupload'));
app.use('/perfilupload', express.static('perfilupload'));

// Ruta de prueba
app.get("/", (req, res) => {
  res.send("El servidor está funcionando correctamente.");
});

// NUEVA RUTA PARA EL LOGIN:

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("Datos recibidos en la solicitud POST /login:", { username });

  if (!username || !password) {
    console.warn("Solicitud inválida: faltan campos obligatorios.");
    return res.status(400).json({ message: "Nombre de usuario y contraseña son obligatorios." });
  }

  const findUserQuery = `
    SELECT 
      u.id, 
      u.name AS usuario, 
      u.password AS contraseña, 
      u.primera_vez, 
      u.dni AS dni, 
      u.nombres AS nombres,
      u.profile_photo_path as foto,
      u.estado AS estado_usuario,
      u.fkidemresa AS fk_idempresa,
      e.nombre AS empresa,
      e.color as color_empresa,
      e.logo as logo,
      v.id as idvehiculo,
      v.placa as placa,
      v.modelo as modelo_vehiculo,
      v.marca as marca,
      v.anio as anio
    FROM users u
    JOIN empresas e ON e.id=u.fkidemresa
    JOIN tipousuarios t ON t.id=u.fkidtipouser
    LEFT JOIN vehiculos v ON v.fkiduser=u.id
    WHERE u.name = ? AND u.estado = 1 AND u.fkidtipouser = 3
  `;

  try {
    const [results] = await db.execute(findUserQuery, [username]);

    if (results.length === 0) {
      console.warn("Usuario no encontrado con el nombre proporcionado.");
      return res.status(401).json({ message: "Credenciales incorrectas." });
    }

    const user = results[0];

    const passwordMatch = await verifyLaravelHash(password, user.contraseña);
    if (!passwordMatch) {
      console.warn("Contraseña incorrecta para el usuario:", username);
      return res.status(401).json({ message: "Credenciales incorrectas." });
    }

    const userData = {
      idUsuarios: user.id,
      dni: user.dni,
      usuario: user.usuario,
      nombres: user.nombres,
      estado: user.estado_usuario,
      foto: user.foto,
      fk_idempresa: user.fk_idempresa,
      empresa: user.empresa,
      idvehiculo: user.idvehiculo,
      placa: user.placa,
      color_empresa: user.color_empresa,
      modelo_vehiculo: user.modelo_vehiculo,
      marca: user.marca,
      anio: user.anio,
      primera_vez: user.primera_vez,
    };

    console.log("Usuario autenticado:", userData.usuario);

    if (userData.primera_vez === 1) {
      return res.status(403).json({
        message: "Es necesario cambiar la contraseña antes de continuar.",
        user: userData,
      });
    }

    return res.status(200).json({
      message: "Inicio de sesión exitoso.",
      user: userData,
    });

  } catch (error) {
    console.error("💥 Error en el endpoint /login:", error);
    return res.status(500).json({ message: "Error interno del servidor al realizar la consulta." });
  }
});

// Función para verificar un hash de contraseña generado por Laravel
function verifyLaravelHash(plainPassword, hashedPassword) {
  return new Promise((resolve, reject) => {
    // Laravel utiliza $2y$ en sus hashes, pero Node.js bcrypt usa $2a$ o $2b$
    // Convertimos el formato si es necesario
    const compatibleHash = hashedPassword.replace(/^\$2y\$/, '$2a$');
    
    bcrypt.compare(plainPassword, compatibleHash, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

// CAMBIAR CONTRASEÑA
app.post("/cambiar-password", async (req, res) => {
  const { username, nuevaContraseña } = req.body;

  if (!username || !nuevaContraseña) {
    return res.status(400).json({ message: "Faltan datos obligatorios." });
  }

  try {
    const hashedPassword = await generateLaravelHash(nuevaContraseña);

    const updatePasswordQuery = `
      UPDATE users
      SET password = ?, primera_vez = 0 
      WHERE name = ?;
    `;

    const [result] = await db.execute(updatePasswordQuery, [hashedPassword, username]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    res.status(200).json({ message: "Contraseña actualizada correctamente." });

  } catch (err) {
    console.error("💥 Error en /cambiar-password:", err);
    return res.status(500).json({ message: "Error al cambiar la contraseña." });
  }
});

/*Función para generar un hash de contraseña compatible con Laravel*/
function generateLaravelHash(plainPassword) {
  return new Promise((resolve, reject) => {
    // Laravel usa un costo de 10 por defecto
    const rounds = 10;
    
    bcrypt.hash(plainPassword, rounds, (err, hash) => {
      if (err) {
        reject(err);
      } else {
        // Convertir el hash de $2a$ o $2b$ (formato Node.js) a $2y$ (formato Laravel)
        const laravelHash = hash.replace(/^\$2[a|b]\$/, '$2y$');
        resolve(laravelHash);
      }
    });
  });
}

// RUTAS PARA EL CERRAR SESION:
app.post("/logout", (req, res) => {
  res.status(200).json({ message: "Sesión cerrada correctamente." });
});

// ENDPOINT PARA OBTENER TURNOS POR VEHÍCULO Y FECHA
app.get("/turnos", async (req, res) => {
  try {
    const { id, fecha } = req.query;

    if (!id || !fecha) {
      return res.status(400).json({
        success: false,
        message: "Se requiere el ID del vehículo y la fecha",
      });
    }

    const moment = require("moment-timezone");

    // Convertimos la fecha a UTC antes de la consulta
    const fechaUTC = moment.tz(fecha, "America/Lima").utc().format("YYYY-MM-DD");

    const query = `
      SELECT 
        t.id,
        t.hora,
        t.fkidestadoturno,
        e.nombre AS estado_actual
      FROM turnos t
      JOIN vehiculos v ON v.id = t.fkidvehiculo
      JOIN estadoturnos e ON e.id = t.fkidestadoturno
      WHERE v.id = ?
      AND DATE(CONVERT_TZ(t.hora, '+00:00', '-05:00')) = ?
      ORDER BY t.hora ASC
    `;

    // ✅ Usamos pool con .execute directamente
    const [turnos] = await db.execute(query, [id, fechaUTC]);

    console.log("🟡 Fecha solicitada:", req.query.fecha);
    console.log("🟢 ID del vehículo:", req.query.id);
    console.log("📦 Turnos obtenidos:", turnos);

    if (turnos.length === 0) {
      return res.json({
        success: true,
        data: [],
        message: "No hay turnos para la fecha seleccionada",
      });
    }

    res.json({
      success: true,
      data: turnos,
    });

  } catch (error) {
    console.error("💥 Error al obtener los turnos:", error);
    res.status(500).json({
      success: false,
      message: "Error al obtener los turnos",
    });
  }
});

//RUTA PARA OBTENER UN TURNO ACTIVO:
app.get("/turno-activo", async (req, res) => {
  let connection;
  try {
    const { id } = req.query;
    console.log("🔍 Buscando turno activo para vehículo:", id);

    // 1. Validar ID del vehículo
    if (!id || isNaN(id)) {
      return res.status(400).json({
        success: false,
        message: "ID de vehículo no válido"
      });
    }

    // 2. Obtener conexión del pool
    connection = await pool.getConnection();

    // 3. Consultar todos los turnos del día (no solo pendientes)
    const queryTurnosDelDia = `
      SELECT 
        t.id,
        DATE_FORMAT(t.hora, '%Y-%m-%d %H:%i:%s') AS hora_programada,
        t.fkidestadoturno,
        TIMESTAMPDIFF(MINUTE, NOW(), t.hora) AS minutos_restantes,
        TIMESTAMPDIFF(HOUR, t.hora, NOW()) AS horas_retraso
      FROM turnos t
      WHERE t.fkidvehiculo = ?
        AND DATE(t.hora) = CURDATE()
      ORDER BY t.hora ASC`;

    const [turnosDelDia] = await connection.execute(queryTurnosDelDia, [id]);

    // 4. Verificar si no hay turnos asignados para hoy
    if (turnosDelDia.length === 0) {
      return res.json({
        success: false,
        message: "No tiene turnos asignados para hoy",
        data: {
          sin_turnos: true
        }
      });
    }

    // 5. Verificar si hay un turno en curso (estado = 2)
    const turnoEnCurso = turnosDelDia.find(turno => turno.fkidestadoturno === 2);
    if (turnoEnCurso) {
      return res.json({
        success: false,
        message: "Ya existe un turno en curso",
        data: {
          turno_en_curso: turnoEnCurso.id
        }
      });
    }

    // 6. Filtrar solo turnos pendientes (estado = 3)
    const turnosPendientes = turnosDelDia.filter(turno => turno.fkidestadoturno === 3);

    // 7. Procesar turnos pendientes
    let turnoElegido = null;
    let diferenciaHoras = 0;
    const turnosADesertar = [];

    for (const turno of turnosPendientes) {
      const horaTurno = moment(turno.hora_programada);
      diferenciaHoras = moment().diff(horaTurno, 'hours');
      
      // Si el turno tiene más de 1 hora de retraso, marcarlo como DESERTO
      if (diferenciaHoras > 1) {
        console.log(`⏳ Turno ${turno.id} con ${diferenciaHoras} horas de retraso - Marcando como DESERTO`);
        turnosADesertar.push(turno.id);
        continue;
      }
      
      // Si encontramos un turno dentro del rango válido
      if (!turnoElegido) {
        turnoElegido = turno;
      }
    }

    // 8. Actualizar turnos desertados (si los hay)
    if (turnosADesertar.length > 0) {
      const queryDesertarTurnos = `
        UPDATE turnos 
        SET fkidestadoturno = 5 /* DESERTO */ 
        WHERE id IN (?)`;
      
      await connection.query(queryDesertarTurnos, [turnosADesertar]);
    }

    // 9. Si no hay turnos válidos después del procesamiento
    if (!turnoElegido) {
      return res.json({
        success: false,
        message: "No hay turnos pendientes dentro del margen horario permitido",
        data: {
          sin_turnos_validos: true
        }
      });
    }

    // 10. Retornar el turno elegido
    res.json({
      success: true,
      data: {
        turno: {
          id: turnoElegido.id,
          hora_programada: turnoElegido.hora_programada,
          estado: turnoElegido.fkidestadoturno,
          minutos_restantes: turnoElegido.minutos_restantes
        },
        puede_iniciar: turnoElegido.minutos_restantes <= 0, // Solo si ya es hora o pasó
        retraso_horas: diferenciaHoras
      }
    });

  } catch (error) {
    console.error("💥 Error en /turno-activo:", error);
    res.status(500).json({
      success: false,
      message: "Error al buscar turno activo"
    });
  } finally {
    // 11. Liberar la conexión de vuelta al pool
    if (connection) {
      connection.release();
    }
  }
});

// RUTA PARA INICIAR VIAJE
app.post("/iniciar-viaje", async (req, res) => {
  let connection;
  try {
    const { idturno, idvehiculo } = req.body;

    // Validación de campos requeridos
    if (!idturno || !idvehiculo) {
      return res.status(400).json({
        success: false,
        message: "Se requiere ID del turno y ID del vehículo",
      });
    }

    // 1. Obtener conexión del pool
    connection = await pool.getConnection();

    // 2. Obtener información completa del turno
    const queryGetTurno = `
      SELECT 
        t.id,
        t.hora AS hora_programada,
        t.fkidestadoturno,
        e.nombre AS estado,
        TIMESTAMPDIFF(HOUR, t.hora, NOW()) AS horas_retraso,
        TIMESTAMPDIFF(MINUTE, NOW(), t.hora) AS minutos_hasta_turno
      FROM turnos t
      JOIN estadoturnos e ON t.fkidestadoturno = e.id
      WHERE t.id = ? AND t.fkidvehiculo = ?`;

    const [turnos] = await connection.execute(queryGetTurno, [idturno, idvehiculo]);

    if (turnos.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Turno no encontrado para este vehículo",
      });
    }

    const turno = turnos[0];
    const horaTurno = moment(turno.hora_programada).tz("America/Lima");
    const ahora = moment().tz("America/Lima");

    // 3. Validar estado actual del turno
    if (turno.fkidestadoturno === 5) { // DESERTO
      return res.status(403).json({
        success: false,
        message: "No se puede iniciar un turno marcado como DESERTO",
      });
    }

    if (turno.fkidestadoturno === 2) { // EN RUTA
      return res.status(409).json({
        success: false,
        message: "Este viaje ya fue iniciado anteriormente",
      });
    }

    if (turno.fkidestadoturno === 4) { // FINALIZADO
      return res.status(403).json({
        success: false,
        message: "No se puede iniciar un turno finalizado",
      });
    }

    // 4. Validar que no sea antes de la hora programada
    const minutosDiferencia = horaTurno.diff(ahora, 'minutes');
    if (minutosDiferencia > 0) {
      return res.status(400).json({
        success: false,
        message: `Aún faltan ${minutosDiferencia} minutos para la hora programada (${horaTurno.format("HH:mm")})`,
        hora_programada: horaTurno.format("YYYY-MM-DD HH:mm:ss"),
        hora_actual: ahora.format("YYYY-MM-DD HH:mm:ss"),
        minutos_restantes: minutosDiferencia,
        puede_iniciar: false
      });
    }

    // 5. Validar límite de 2 horas de retraso
    if (turno.horas_retraso > 2) {
      // Actualizar estado a DESERTO
      await connection.execute(
        `UPDATE turnos SET fkidestadoturno = 5 WHERE id = ?`,
        [idturno]
      );
      
      return res.status(403).json({
        success: false,
        message: "El turno ha sido marcado como DESERTO por exceder el límite de 2 horas de retraso",
      });
    }

    // 6. Actualizar estado del turno a EN RUTA (2)
    await connection.execute(
      `UPDATE turnos SET fkidestadoturno = 2 WHERE id = ?`,
      [idturno]
    );

    res.json({
      success: true,
      message: "Viaje iniciado correctamente",
      data: {
        id_turno: turno.id,
        hora_programada: horaTurno.format("HH:mm"),
        hora_inicio: ahora.format("HH:mm"),
        estado: "EN RUTA",
        retraso_horas: turno.horas_retraso || 0
      }
    });

  } catch (error) {
    console.error("Error al iniciar viaje:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al iniciar el viaje",
    });
  } finally {
    // 7. Liberar la conexión de vuelta al pool
    if (connection) {
      connection.release();
    }
  }
});

// RUTA PARA LOS VIAJES ACTIVOS
app.get('/viaje-activo', async (req, res) => {
  const { idvehiculo } = req.query;

  if (!idvehiculo) {
    return res.status(400).json({ success: false, message: 'Falta el id del vehículo' });
  }

  let connection;
  try {
    // 1. Obtener conexión del pool
    connection = await pool.getConnection();

    // 2. Consultar turno activo
    const [turno] = await connection.query(`
      SELECT * FROM turnos
      WHERE fkidvehiculo = ? AND fkidestadoturno = 2
      ORDER BY hora DESC
      LIMIT 1
    `, [idvehiculo]);

    if (turno.length === 0) {
      return res.json({ success: true, viaje_activo: false });
    }

    return res.json({ success: true, viaje_activo: true, turno: turno[0] });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Error al consultar', error: err.message });
  } finally {
    // 3. Liberar la conexión de vuelta al pool
    if (connection) {
      connection.release();
    }
  }
});

// RUTA PARA CARGAR LOS PUNTOS MARCADOS DEL VIAJE ACTIVO
app.get('/puntos-marcados', async (req, res) => {
  const { idvehiculo } = req.query;

  let connection;
  try {
    // 1. Obtener conexión del pool
    connection = await pool.getConnection();

    // 2. Obtener turno activo
    const [turno] = await connection.query(`
      SELECT id FROM turnos 
      WHERE fkidvehiculo = ? AND fkidestadoturno = 2
      LIMIT 1
    `, [idvehiculo]);

    if (!turno.length) {
      return res.json({ success: true, puntos: [] });
    }

    // 3. Obtener todos los puntos del turno
    const [puntosTurno] = await connection.query(`
      SELECT p.id, p.nombre, p.latitud, p.longitud, p.orden,
          m.id AS id_marcado, m.fecha, m.latitud AS lat_marcado, 
          m.longitud AS lon_marcado, m.diferencia,
          th.id AS idTurnoHora 
      FROM turno_horas th
      JOIN puntos p ON th.fkidpunto = p.id
      LEFT JOIN marcados m ON th.id = m.fkidturnohora
      WHERE th.fkidturno = ?
      ORDER BY p.orden
    `, [turno[0].id]);

    // 4. Formatear respuesta
    const puntosFormateados = puntosTurno.map(p => ({
      id: p.id,
      nombre: p.nombre,
      latitud: p.latitud,
      longitud: p.longitud,
      orden: p.orden,
      estado: p.id_marcado ? "marcado" : "sin marcar",
      hora: p.fecha,
      diferencia: p.diferencia,
      idTurnoHora: p.idTurnoHora
    }));

    res.json({ success: true, puntos: puntosFormateados });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  } finally {
    // 5. Liberar la conexión de vuelta al pool
    if (connection) {
      connection.release();
    }
  }
});

// Ejecutar diariamente a las 00:00
app.get('/limpiar-turnos', async (req, res) => {
  try {
    const [resultado] = await db.execute(`
      UPDATE turnos 
      SET fkidestadoturno = 5 
      WHERE DATE(hora) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
        AND fkidestadoturno = 3
    `);

    res.json({
      success: true,
      message: `Turnos actualizados correctamente.`,
      filas_afectadas: resultado.affectedRows
    });
    
  } catch (error) {
    console.error("💥 Error al limpiar turnos:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al limpiar los turnos"
    });
  }
});

// Ruta para mostrar los puntos con ordenamiento y filtro por ruta
app.get("/puntos", async (req, res) => {
  try {
    const { fk_idempresa, idvehiculo } = req.query;

    // ✅ Validación de parámetros
    if (!fk_idempresa || !idvehiculo) {
      return res.status(400).json({
        success: false,
        error: "Se requieren los parámetros fk_idempresa e idvehiculo"
      });
    }

    // 📄 Consulta SQL
    const sqlQuery = `
      SELECT DISTINCT
        p.id AS id, 
        p.nombre AS nombre, 
        p.latitud, 
        p.longitud, 
        p.orden, 
        p.fkidruta,
        r.nombre AS nombre_ruta
      FROM puntos p
      JOIN rutas r ON r.id = p.fkidruta
      JOIN empresas e ON e.id = r.fkidempresa
      JOIN turno_horas tr ON tr.fkidpunto = p.id
      JOIN turnos t ON t.id = tr.fkidturno
      JOIN vehiculos v ON v.id = t.fkidvehiculo
      WHERE e.id = ? AND v.id = ?
      ORDER BY p.orden ASC
    `;

    // 📡 Ejecución de la consulta
    const [result] = await db.execute(sqlQuery, [fk_idempresa, idvehiculo]);

    // 📤 Respuesta
    if (result.length === 0) {
      return res.status(200).json({
        success: true,
        message: "No se encontraron puntos de marcado para el vehículo y empresa especificados.",
        data: []
      });
    }

    res.json({
      success: true,
      data: result
    });

  } catch (err) {
    console.error("💥 Error al obtener los puntos:", err);
    res.status(500).json({
      success: false,
      error: "Error interno al obtener los puntos de marcado"
    });
  }
});

// RUTA PARA CALCULAR DIFERENCIA DE HORAS AL MARCAR
app.post("/calcular-diferencia", async (req, res) => {
  try {
    const { hora_salida_turno, fkidturnohora, hora_marcado } = req.body;

    console.log("📥 Datos recibidos:", { hora_salida_turno, fkidturnohora, hora_marcado });

    // 1. Validar entrada
    if (!hora_salida_turno || !fkidturnohora || !hora_marcado) {
      return res.status(400).json({
        success: false,
        message: "Faltan datos obligatorios: hora_salida_turno, fkidturnohora o hora_marcado"
      });
    }

    // 2. Obtener tiempo programado del punto - CAMBIO: db.promise().execute() → db.execute()
    console.log("🔍 Consultando turno_horas con ID:", fkidturnohora);
    
    const [turnoHoraResult] = await db.execute(
      `SELECT tiempo, fkidpunto, p.orden 
       FROM turno_horas th 
       JOIN puntos p ON th.fkidpunto = p.id
       WHERE th.id = ?`,
      [fkidturnohora]
    );

    console.log("📊 Resultado de consulta:", turnoHoraResult);

    if (!turnoHoraResult || turnoHoraResult.length === 0) {
      console.error("❌ No se encontró turno_hora con ID:", fkidturnohora);
      return res.status(404).json({
        success: false,
        message: `No se encontró la programación del punto para turno_hora ID: ${fkidturnohora}`
      });
    }

    const { tiempo, fkidpunto, orden } = turnoHoraResult[0];
    console.log("✅ Datos del punto:", { tiempo, fkidpunto, orden });

    // 3. Validar formato de tiempo
    if (!tiempo || typeof tiempo !== 'string') {
      console.error("❌ Formato de tiempo inválido:", tiempo);
      return res.status(400).json({
        success: false,
        message: `Formato de tiempo inválido: ${tiempo}`
      });
    }

    // 4. Calcular diferencia - LÓGICA MEJORADA
    console.log("⏰ Calculando diferencia...");
    
    // Verificar formato de tiempo (debe ser HH:MM o HH:MM:SS)
    const tiempoPartes = tiempo.split(':');
    if (tiempoPartes.length < 2) {
      console.error("❌ Formato de tiempo inválido:", tiempo);
      return res.status(400).json({
        success: false,
        message: `Formato de tiempo inválido: ${tiempo}. Debe ser HH:MM o HH:MM:SS`
      });
    }

    const horas = parseInt(tiempoPartes[0]);
    const minutos = parseInt(tiempoPartes[1]);
    
    if (isNaN(horas) || isNaN(minutos)) {
      console.error("❌ Error parseando tiempo:", { horas, minutos });
      return res.status(400).json({
        success: false,
        message: `Error al parsear tiempo: ${tiempo}`
      });
    }

    const totalMinutos = (horas * 60) + minutos;
    console.log("📊 Tiempo programado en minutos:", totalMinutos);

    // Crear objetos moment con validación
    const momentSalida = moment(hora_salida_turno);
    const momentMarcado = moment(hora_marcado);

    if (!momentSalida.isValid() || !momentMarcado.isValid()) {
      console.error("❌ Fechas inválidas:", {
        hora_salida_turno: momentSalida.isValid(),
        hora_marcado: momentMarcado.isValid()
      });
      return res.status(400).json({
        success: false,
        message: "Formato de fecha inválido"
      });
    }

    const horaEsperada = momentSalida.add(totalMinutos, 'minutes');
    console.log("🎯 Hora esperada:", horaEsperada.format('YYYY-MM-DD HH:mm:ss'));
    console.log("⏱️ Hora marcado:", momentMarcado.format('YYYY-MM-DD HH:mm:ss'));
    
    // CORRECCIÓN: Invertir el orden del cálculo
    // horaMarcado.diff(horaEsperada) → +: retrasado, -: adelantado
    const diferencia = momentMarcado.diff(horaEsperada, 'minutes');
    console.log("📊 Diferencia calculada:", diferencia, "minutos");

    // 5. Determinar estado más claro
    let estado;
    if (diferencia > 0) {
      estado = `Con retraso de ${diferencia} minutos`;
    } else if (diferencia < 0) {
      estado = `Adelantado por ${Math.abs(diferencia)} minutos`;
    } else {
      estado = "A tiempo exacto";
    }

    console.log("✅ Estado final:", estado);

    // 6. Preparar respuesta
    const respuesta = {
      success: true,
      data: {
        diferencia_minutos: diferencia,
        hora_esperada: horaEsperada.format('YYYY-MM-DD HH:mm:ss'),
        hora_marcado: momentMarcado.format('YYYY-MM-DD HH:mm:ss'),
        tiempo_programado: tiempo,
        idpunto: fkidpunto,
        orden_punto: orden,
        estado: estado
      }
    };

    console.log("📤 Enviando respuesta:", respuesta);
    res.json(respuesta);
    
  } catch (error) {
    console.error("💥 Error detallado:", error);
    res.status(500).json({
      success: false,
      message: "Error en el cálculo de diferencia",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// RUTA PARA VERIFICAR SI ESTOY EN EL RANGO DE UN PUNTO AL MARCAR
const RADIUS_EARTH = 6371e3; // Radio de la Tierra en metros (6371 km)

// Función para calcular la distancia entre dos puntos usando la fórmula de Haversine
function calcularDistancia(lat1, lon1, lat2, lon2) {
  const radianes = Math.PI / 180;

  const lat1Rad = lat1 * radianes;
  const lon1Rad = lon1 * radianes;
  const lat2Rad = lat2 * radianes;
  const lon2Rad = lon2 * radianes;

  const dLat = lat2Rad - lat1Rad;
  const dLon = lon2Rad - lon1Rad;

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1Rad) * Math.cos(lat2Rad) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return RADIUS_EARTH * c; // Distancia en metros
}

// Endpoint para verificar si el usuario está dentro del radio
app.post("/verificar-rango", async (req, res) => {
  try {
    const { latitudMarcado, longitudMarcado, idpunto, idturno } = req.body;

    // Validaciones mejoradas
    if (!latitudMarcado || !longitudMarcado || !idpunto || !idturno) {
      return res.status(400).json({
        success: false,
        message: "Se requieren: latitud, longitud, idpunto e idturno"
      });
    }

    // 1. Verificar que el punto pertenece al turno - CAMBIO: db.promise().execute() → db.execute()
    const [puntoTurno] = await db.execute(
      `SELECT p.latitud, p.longitud, p.orden 
       FROM puntos p
       JOIN turno_horas th ON th.fkidpunto = p.id
       WHERE p.id = ? AND th.fkidturno = ?`,
      [idpunto, idturno]
    );

    if (puntoTurno.length === 0) {
      return res.status(404).json({
        success: false,
        message: "El punto no pertenece al turno especificado"
      });
    }

    const punto = puntoTurno[0];
    const distancia = calcularDistancia(
      latitudMarcado, 
      longitudMarcado, 
      punto.latitud, 
      punto.longitud
    );

   // 2. Validar distancia (45m máximo) - ACTUALIZADO
    const RANGO_PERMITIDO = 45; // metros
    const dentroDelRango = distancia <= RANGO_PERMITIDO;
    const mensaje = dentroDelRango 
      ? `Está dentro del rango permitido (${RANGO_PERMITIDO}m)` 
      : `Está a ${distancia.toFixed(1)}m del punto (máximo ${RANGO_PERMITIDO}m permitidos)`;

    res.json({
      success: dentroDelRango,
      data: {
        dentroDelRango,
        distancia: distancia.toFixed(1),
        orden_punto: punto.orden,
        punto: {
          latitud: punto.latitud,
          longitud: punto.longitud
        },
        ubicacionActual: {
          latitud: latitudMarcado,
          longitud: longitudMarcado
        }
      },
      message: mensaje
    });

  } catch (error) {
    console.error("Error en /verificar-rango:", error);
    res.status(500).json({
      success: false,
      message: "Error al verificar ubicación"
    });
  }
});

// RUTA PARA MARCAR PUNTO
app.post("/marcarpunto", async (req, res) => {
  try {
    const { 
      fecha, 
      celular, 
      longitud, 
      latitud, 
      diferencia, 
      fkidturnohora,
      deviceId
    } = req.body;

    // Validación mejorada
    if (!fkidturnohora || !latitud || !longitud) {
      return res.status(400).json({
        success: false,
        message: "Datos incompletos: se requieren fkidturnohora, latitud y longitud"
      });
    }

    // 1. Verificar turno_hora 
    const [turnoHora] = await db.execute(
      `SELECT th.id, t.hora AS hora_salida_turno
       FROM turno_horas th
       JOIN turnos t ON t.id = th.fkidturno
       WHERE th.id = ?`,
      [fkidturnohora]
    );

    if (turnoHora.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Relación turno-hora no encontrada"
      });
    }

    // 2. Insertar marcación con valores por defecto - CAMBIO: db.promise().execute() → db.query()
    const fechaMarcado = fecha || new Date().toISOString();
    const diferenciaCalculada = diferencia || 0;
    const celularInfo = celular || JSON.stringify({ deviceId });

    const [result] = await db.query(
      `INSERT INTO marcados (
        fecha, celular, longitud, latitud, 
        diferencia, fkidturnohora,estado
      ) VALUES (?, ?, ?, ?, ?, ?, 1)`,
      [
        fechaMarcado,
        celularInfo,
        longitud,
        latitud,
        diferenciaCalculada,
        fkidturnohora,
      ]
    );

    res.json({
      success: true,
      data: {
        id_marcacion: result.insertId,
        hora_marcado: fechaMarcado,
        diferencia: diferenciaCalculada
      },
      message: "Punto marcado correctamente"
    });

  } catch (error) {
    console.error("Error en /marcarpunto:", error);
    res.status(500).json({
      success: false,
      message: "Error al registrar marcación",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.get('/puntos-turno', async (req, res) => {
  try {
    const { idturno } = req.query;
    
    console.log("🔍 Buscando puntos para turno:", idturno);
    
    if (!idturno || isNaN(idturno)) {
      return res.status(400).json({
        success: false,
        message: "Se requiere un idturno válido"
      });
    }

    // Usar el mismo método que en otros endpoints para consistencia
    const queryPuntos = `
      SELECT 
        p.id, 
        p.nombre, 
        p.latitud, 
        p.longitud,
        th.id AS idTurnoHora, 
        p.orden, 
        th.tiempo
      FROM turno_horas th
      JOIN puntos p ON p.id = th.fkidpunto
      WHERE th.fkidturno = ?
      ORDER BY p.orden ASC`;

    // CAMBIO: db.promise().execute() → db.execute()
    const [puntos] = await db.execute(queryPuntos, [idturno]);
    
    console.log(`📍 Puntos encontrados para turno ${idturno}:`, puntos.length);
    
    if (puntos.length === 0) {
      console.log("⚠️ No se encontraron puntos para este turno");
      return res.json({
        success: false,
        message: "No se encontraron puntos para este turno",
        data: []
      });
    }
    
    // Log detallado de los puntos encontrados
    puntos.forEach((punto, index) => {
      console.log(`  ${index + 1}. ${punto.nombre} (ID: ${punto.id}, Orden: ${punto.orden})`);
    });

    res.json({
      success: true,
      data: puntos,
      message: `${puntos.length} puntos cargados correctamente`
    });
    
  } catch (error) {
    console.error("💥 Error en /puntos-turno:", error);
    res.status(500).json({
      success: false,
      message: "Error al obtener puntos del turno",
      error: error.message
    });
  }
});

// RUTA PARA OBTENER INCIDENTES POR TURNO
app.get("/incidentes_por_turno/:idTurno", async (req, res) => {
  try {
    const [incidentes] = await pool.execute(
      `SELECT id, descripcion, hora, foto 
       FROM incidentes 
       WHERE fkidturno = ? 
       ORDER BY hora DESC`,
      [req.params.idTurno]
    );
    res.json({ success: true, data: incidentes });
  } catch (error) {
    console.error("Error en /incidentes_por_turno:", error);
    res.status(500).json({ success: false, message: "Error al obtener incidentes" });
  }
});

// RUTA PARA OMITIR PUNTO DE MARCADO
app.post("/omitir_punto", async (req, res) => {
  let connection;
  try {
    const { fk_idturno, fk_idpunto, fkidestadomarcado, celular = '', observacion = '' } = req.body;

    console.log("========== INICIANDO REGISTRO DE OMISIÓN ==========");
    console.log("Datos recibidos en req.body:", req.body);

    if (!fk_idturno || !fk_idpunto || !fkidestadomarcado) {
      console.warn("Faltan datos requeridos:", { fk_idturno, fk_idpunto, fkidestadomarcado });
      return res.status(400).json({
        success: false,
        message: "Faltan datos requeridos",
        datos_recibidos: { fk_idturno, fk_idpunto, fkidestadomarcado },
      });
    }

    // 1. Obtener conexión del pool
    connection = await pool.getConnection();

    // 2. Buscar el ID de turno_hora relacionado con el turno y el punto
    const [turnoHoraResult] = await connection.query(`
      SELECT id FROM turno_horas
      WHERE fkidturno = ? AND fkidpunto = ?
      LIMIT 1
    `, [fk_idturno, fk_idpunto]);

    if (turnoHoraResult.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No se encontró una coincidencia en turno_hora",
      });
    }

    const fkidturnohora = turnoHoraResult[0].id;

    // 3. Insertar registro de omisión
    const insertQuery = `
      INSERT INTO marcados (fecha, celular, longitud, latitud, observacion, diferencia, estado, fkidestadomarcado, fkidturnohora)
      VALUES (NOW(), ?, NULL, NULL, ?, NULL, 0, ?, ?)
    `;

    const [insertResult] = await connection.execute(insertQuery, [
      celular,
      observacion,
      fkidestadomarcado,
      fkidturnohora
    ]);

    if (insertResult.affectedRows === 1) {
      console.log("✅ Punto omitido registrado correctamente.");
      return res.json({
        success: true,
        message: "Omisión de punto registrada exitosamente",
        idmarcado: insertResult.insertId,
      });
    } else {
      console.error("⚠️ No se insertó el registro.");
      return res.status(500).json({
        success: false,
        message: "Error al registrar la omisión de punto",
      });
    }
  } catch (error) {
    console.error("❌ Error al registrar la omisión de punto:", error.stack);
    res.status(500).json({
      success: false,
      message: "Error interno del servidor",
    });
  } finally {
    // 4. Liberar la conexión de vuelta al pool
    if (connection) {
      connection.release();
    }
  }
});

// Finalizar turno
app.post("/finalizar-turno", async (req, res) => {
  let connection;
  try {
    const { idTurno } = req.body;

    console.log("🔚 Finalizando turno:", idTurno);

    if (!idTurno) {
      return res.status(400).json({
        success: false,
        message: "Se requiere el ID del turno"
      });
    }

    // 1. Obtener conexión del pool
    connection = await pool.getConnection();

    // 2. Verificar que el turno existe y está en estado EN RUTA (2)
    const queryVerificar = `
      SELECT id, fkidestadoturno 
      FROM turnos 
      WHERE id = ?`;
    
    const [turnoInfo] = await connection.execute(queryVerificar, [idTurno]);

    if (turnoInfo.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Turno no encontrado"
      });
    }

    const turno = turnoInfo[0];

    if (turno.fkidestadoturno !== 2) {
      return res.status(400).json({
        success: false,
        message: "El turno no está en estado EN RUTA"
      });
    }

    // 3. Actualizar estado del turno a FINALIZADO (4)
    await connection.execute(
      `UPDATE turnos SET fkidestadoturno = 4 WHERE id = ?`,
      [idTurno]
    );

    console.log("✅ Turno finalizado exitosamente:", idTurno);

    res.json({
      success: true,
      message: "Turno finalizado correctamente",
      data: {
        id_turno: idTurno,
        hora_finalizacion: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error("💥 Error al finalizar turno:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al finalizar el turno"
    });
  } finally {
    // 4. Liberar la conexión de vuelta al pool
    if (connection) {
      connection.release();
    }
  }
});
// Ruta para la vista previa y descarga del historial de rrecorrido

// Endpoint para obtener vista previa
app.get("/vista-previa/:idturno", async (req, res) => {
  const { idturno } = req.params;
  console.log("Consultando vista previa para turno:", idturno);
  
  try {
    // 1. Información básica del turno
    const [infoTurno] = await pool.execute(
      `SELECT 
          t.id,
          u.nombres AS conductor,
          v.placa AS vehiculo
       FROM turnos t
       JOIN vehiculos v ON v.id = t.fkidvehiculo
       JOIN users u ON u.id = v.fkiduser
       WHERE t.id = ?`,
      [idturno]
    );

    if (infoTurno.length === 0) {
      return res.status(404).json({
        error: 'No se encontró el turno',
        message: 'El turno especificado no existe'
      });
    }

    // 2. Puntos marcados
    const [puntosMarcados] = await pool.execute(
      `SELECT 
          m.id AS id_marcado,
          ps.nombre AS punto_marcado,
          m.fecha AS hora_marcado,
          m.diferencia,
          m.latitud,
          m.longitud,
          'marcado' AS tipo_registro
       FROM marcados m
       JOIN turno_horas th ON th.id = m.fkidturnohora
       JOIN puntos ps ON ps.id = th.fkidpunto
       WHERE th.fkidturno = ?
       ORDER BY m.fecha`,
      [idturno]
    );

    // 3. Incidentes
    const [incidentes] = await pool.execute(
      `SELECT 
          i.id AS id_incidente,
          i.hora AS hora_incidente,
          i.descripcion AS descripcion_incidente,
          i.foto AS foto_incidente,
          i.latitud,
          i.longitud,
          'incidente' AS tipo_registro
       FROM incidentes i
       WHERE i.fkidturno = ?
       ORDER BY i.hora`,
      [idturno]
    );

    // 4. Combinar y responder
    const resultado = {
      conductor: infoTurno[0].conductor,
      vehiculo: infoTurno[0].vehiculo,
      puntos_marcados: puntosMarcados,
      incidentes: incidentes
    };

    console.log("Datos de vista previa:", resultado);
    res.json(resultado);

  } catch (error) {
    console.error("Error en vista previa:", error);
    res.status(500).json({ 
      error: 'Error al obtener los datos', 
      message: error.message
    });
  }
});

//ENDPOINT PARA DESCARGAR EN PDF
app.get("/dowpdf/:idturno", async (req, res) => {
  const { idturno } = req.params;

  try {
    const [infoTurno] = await pool.execute(
      `SELECT t.id, u.nombres AS conductor, v.placa AS vehiculo
       FROM turnos t
       JOIN vehiculos v ON v.id = t.fkidvehiculo
       JOIN users u ON u.id = v.fkiduser
       WHERE t.id = ?`,
      [idturno]
    );

    if (infoTurno.length === 0) {
      return res.status(404).json({ error: "Turno no encontrado" });
    }

    const [puntos] = await pool.execute(
      `SELECT ps.nombre AS punto_marcado, m.fecha AS hora_marcado,
              m.diferencia, m.latitud, m.longitud
       FROM marcados m
       JOIN turno_horas th ON th.id = m.fkidturnohora
       JOIN puntos ps ON ps.id = th.fkidpunto
       WHERE th.fkidturno = ?
       ORDER BY m.fecha`,
      [idturno]
    );

    const [incidentes] = await pool.execute(
      `SELECT i.hora AS hora_incidente, i.descripcion AS descripcion_incidente,
              i.foto AS foto_incidente, i.latitud, i.longitud
       FROM incidentes i
       WHERE i.fkidturno = ?
       ORDER BY i.hora`,
      [idturno]
    );

    // Crear PDF
    const doc = new PDFDocument({ margin: 50 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=turno_${idturno}.pdf`
    );
    doc.pipe(res);

    // Encabezado
    doc.fontSize(20).text("REPORTE DE TURNO", { align: "center" });
    doc.moveDown();
    doc.fontSize(14).text(`Turno ID: ${idturno}`);
    doc.text(`Conductor: ${infoTurno[0].conductor}`);
    doc.text(`Vehículo: ${infoTurno[0].vehiculo}`);
    doc.moveDown();

    // Puntos marcados
    doc.fontSize(16).text("PUNTOS MARCADOS", { underline: true });
    doc.moveDown(0.5);
    puntos.forEach((p, i) => {
      doc.fontSize(12).text(`${i + 1}. Punto: ${p.punto_marcado}`);
      doc.text(`   Fecha: ${p.hora_marcado}`);
      doc.text(`   Diferencia: ${p.diferencia}`);
      doc.text(`   Ubicación: [${p.latitud}, ${p.longitud}]`);
      doc.moveDown(0.5);
    });

    // Incidentes
    doc.addPage();
    doc.fontSize(16).text("INCIDENTES", { underline: true });
    doc.moveDown(0.5);

    for (let i = 0; i < incidentes.length; i++) {
      const inc = incidentes[i];
      doc.fontSize(12).text(`${i + 1}. Hora: ${inc.hora_incidente}`);
      doc.text(`   Descripción: ${inc.descripcion_incidente}`);
      doc.text(`   Ubicación: [${inc.latitud}, ${inc.longitud}]`);

      const imagePath = path.join(__dirname, "uploads", inc.foto_incidente);
      if (fs.existsSync(imagePath)) {
        doc.image(imagePath, {
          width: 200,
          align: "left",
        });
      } else {
        doc.text("   Imagen no disponible");
      }

      doc.moveDown();
    }

    doc.end();
  } catch (error) {
    console.error("Error al generar PDF:", error);
    res.status(500).json({ error: "Error generando PDF" });
  }
});

// Iniciar el servidor con valores dinámicos
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
