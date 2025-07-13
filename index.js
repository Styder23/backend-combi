require("dotenv").config(); // Carga las variables de entorno
const express = require("express");
const mysql = require("mysql2");
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

// Configuración de la conexión a MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST, // Dirección de tu servidor MySQL
  user: process.env.DB_USER, // Usuario de MySQL
  password: process.env.DB_PASSWORD, // Contraseña de MySQL
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT) || 3306 // Nombre de la base de datos
});

// Conexión a la base de datos
db.connect((err) => {
  if (err) {
    console.error("Error al conectar a la base de datos:", err);
    return;
  }
  console.log("Conexión exitosa a la base de datos MySQL.");
});

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

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  console.log("Datos recibidos en la solicitud POST /login:", { username });

  // Validar campos obligatorios
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

  // Ejecutar consulta para buscar al usuario por name
  db.query(findUserQuery, [username], (err, results) => {
    if (err) {
      console.error("Error en la consulta SQL:", err);
      return res.status(500).json({ message: "Error interno del servidor al realizar la consulta." });
    }

    if (results.length === 0) {
      console.warn("Usuario no encontrado con el nombre proporcionado.");
      return res.status(401).json({ message: "Credenciales incorrectas." });
    }

    const user = results[0];
    
    // Verificar la contraseña usando el método de Laravel
    verifyLaravelHash(password, user.contraseña)
      .then(passwordMatch => {
        if (!passwordMatch) {
          console.warn("Contraseña incorrecta para el usuario:", username);
          return res.status(401).json({ message: "Credenciales incorrectas." });
        }
        
        // Credenciales correctas, construir el objeto de respuesta
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
        
        // Si el usuario debe cambiar su contraseña
        if (userData.primera_vez === 1) {
          console.warn("El usuario debe cambiar su contraseña.");
          return res.status(403).json({
            message: "Es necesario cambiar la contraseña antes de continuar.",
            user: userData,
          });
        }

        // Inicio de sesión exitoso
        res.status(200).json({
          message: "Inicio de sesión exitoso.",
          user: userData,
        });
      })
      .catch(error => {
        console.error("Error al verificar la contraseña:", error);
        return res.status(500).json({ message: "Error interno del servidor al verificar credenciales." });
      });
  });
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
app.post("/cambiar-password", (req, res) => {
  const { username, nuevaContraseña } = req.body;

  if (!username || !nuevaContraseña) {
    return res.status(400).json({ message: "Faltan datos obligatorios." });
  }

  // Generar hash de la nueva contraseña compatible con Laravel
  generateLaravelHash(nuevaContraseña)
    .then(hashedPassword => {
      const updatePasswordQuery = `
        UPDATE users
        SET password = ?, primera_vez = 0 
        WHERE name = ?;
      `;

      db.query(updatePasswordQuery, [hashedPassword, username], (err, result) => {
        if (err) {
          console.error("Error al actualizar contraseña:", err);
          return res.status(500).json({ message: "Error al cambiar la contraseña." });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "Usuario no encontrado." });
        }

        res.status(200).json({ message: "Contraseña actualizada correctamente." });
      });
    })
    .catch(err => {
      console.error("Error al generar hash de contraseña:", err);
      return res.status(500).json({ message: "Error al procesar la nueva contraseña." });
    });
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

    const [turnos] = await db.promise().execute(query, [id, fechaUTC]);
    console.log(req.query.fecha)
    console.log(req.query.id)
    console.log("Turnos obtenidos:", turnos);

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
    console.error("Error al obtener los turnos:", error);
    res.status(500).json({
      success: false,
      message: "Error al obtener los turnos",
    });
  }
});

//RUTA PARA OBTENER UN TURNO ACTIVO:
app.get("/turno-activo", async (req, res) => {
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

    // 2. Consultar turnos del día pendientes (estado = 3)
    const queryTurnosPendientes = `
      SELECT 
        t.id,
        DATE_FORMAT(t.hora, '%Y-%m-%d %H:%i:%s') AS hora_programada,
        t.fkidestadoturno,
        TIMESTAMPDIFF(MINUTE, NOW(), t.hora) AS minutos_restantes
      FROM turnos t
      WHERE t.fkidvehiculo = ?
        AND DATE(t.hora) = CURDATE()
        AND t.fkidestadoturno = 3 
      ORDER BY t.hora ASC`;

    const [turnosPendientes] = await db.promise().execute(queryTurnosPendientes, [id]);

    // 3. Procesar turnos pendientes
    let turnoElegido = null;
    let diferenciaHoras = 0;
    const turnosADesertar = [];

    for (const turno of turnosPendientes) {
      const horaTurno = moment(turno.hora_programada);
      diferenciaHoras = moment().diff(horaTurno, 'hours');
      
      // Si el turno tiene más de 2 horas de retraso
      if (diferenciaHoras > 2) {
        console.log(`⏳ Turno ${turno.id} con ${diferenciaHoras} horas de retraso - Marcando como DESERTO`);
        turnosADesertar.push(turno.id);
        continue;
      }
      
      // Si encontramos un turno dentro del rango válido
      if (!turnoElegido) {
        turnoElegido = turno;
      }
    }

    // 4. Actualizar turnos desertados (si los hay)
    if (turnosADesertar.length > 0) {
      const queryDesertarTurnos = `
        UPDATE turnos 
        SET fkidestadoturno = 5 /* DESERTO */ 
        WHERE id IN (?)`;
      
      await db.promise().query(queryDesertarTurnos, [turnosADesertar]);
    }

    // 5. Si no hay turnos válidos
    if (!turnoElegido) {
      return res.status(404).json({
        success: false,
        message: "No hay turnos pendientes dentro del margen horario permitido"
      });
    }

    // 6. Verificar si hay un turno en curso (estado = 2)
    const queryTurnoEnCurso = `
      SELECT id FROM turnos 
      WHERE fkidvehiculo = ? 
        AND fkidestadoturno = 2
        AND DATE(hora) = CURDATE()`;
    
    const [enCurso] = await db.promise().execute(queryTurnoEnCurso, [id]);
    
    if (enCurso.length > 0) {
      return res.json({
        success: false,
        message: "Ya existe un turno en curso",
        data: {
          turno_en_curso: enCurso[0].id
        }
      });
    }

    // 7. Retornar el turno elegido
    res.json({
      success: true,
      data: {
        turno: {
          id: turnoElegido.id,
          hora_programada: turnoElegido.hora_programada,
          estado: turnoElegido.fkidestadoturno
        },
        puede_iniciar: true,
        retraso_horas: diferenciaHoras
      }
    });

  } catch (error) {
    console.error("💥 Error en /turno-activo:", error);
    res.status(500).json({
      success: false,
      message: "Error al buscar turno activo"
    });
  }
});

// RUTA PARA INICIAR VIAJE
app.post("/iniciar-viaje", async (req, res) => {
  try {
    const { idturno, idvehiculo } = req.body;

    // Validación de campos requeridos
    if (!idturno || !idvehiculo) {
      return res.status(400).json({
        success: false,
        message: "Se requiere ID del turno y ID del vehículo",
      });
    }

    // 1. Obtener información completa del turno
    const queryGetTurno = `
      SELECT 
        t.id,
        t.hora AS hora_programada,
        t.fkidestadoturno,
        e.nombre AS estado,
        TIMESTAMPDIFF(HOUR, t.hora, NOW()) AS horas_retraso
      FROM turnos t
      JOIN estadoturnos e ON t.fkidestadoturno = e.id
      WHERE t.id = ? AND t.fkidvehiculo = ?`;

    const [turnos] = await db.promise().execute(queryGetTurno, [idturno, idvehiculo]);

    if (turnos.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Turno no encontrado para este vehículo",
      });
    }

    const turno = turnos[0];
    const horaTurno = moment(turno.hora_programada).tz("America/Lima");
    const ahora = moment().tz("America/Lima");

    // 2. Validar estado actual del turno
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

    // 3. Validar límite de 2 horas de retraso
    if (turno.horas_retraso > 2) {
      // Actualizar estado a DESERTO
      await db.promise().execute(
        `UPDATE turnos SET fkidestadoturno = 5 WHERE id = ?`,
        [idturno]
      );
      
      return res.status(403).json({
        success: false,
        message: "El turno ha sido marcado como DESERTO por exceder el límite de 2 horas de retraso",
      });
    }

    // 4. Validar que no sea antes de la hora programada
    const minutosDiferencia = horaTurno.diff(ahora, 'minutes');
    if (minutosDiferencia > 0) {
      return res.status(400).json({
        success: false,
        message: `No se puede iniciar el viaje antes de la hora programada (${horaTurno.format("HH:mm")})`,
        hora_programada: horaTurno.format("YYYY-MM-DD HH:mm:ss"),
        hora_actual: ahora.format("YYYY-MM-DD HH:mm:ss"),
        minutos_restantes: minutosDiferencia
      });
    }

    // 5. Actualizar estado del turno a EN RUTA (2)
    await db.promise().execute(
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
        retraso_horas: turno.horas_retraso
      }
    });

  } catch (error) {
    console.error("Error al iniciar viaje:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al iniciar el viaje",
    });
  }
});

// Ejecutar diariamente a las 00:00
app.get('/limpiar-turnos', async (req, res) => {
  // Marcar como DESERTO todos los turnos del día anterior con estado 3
  await db.execute(`
    UPDATE turnos 
    SET fkidestadoturno = 5 
    WHERE DATE(hora) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
    AND fkidestadoturno = 3
  `);
  res.json({success: true});
});

// Ruta para mostrar los puntos con ordenamiento y filtro por ruta
app.get("/puntos", (req, res) => {
  const { fk_idempresa, idvehiculo } = req.query;

  // Validación de parámetros requeridos
  if (!fk_idempresa || !idvehiculo) {
    return res.status(400).json({ 
      success: false,
      error: "Se requieren los parámetros fk_idempresa e idvehiculo" 
    });
  }

  // Consulta SQL mejorada
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
    ORDER BY p.orden ASC`;

  db.query(sqlQuery, [fk_idempresa, idvehiculo], (err, result) => {
    if (err) {
      console.error("Error al obtener los puntos:", err);
      return res.status(500).json({ 
        success: false,
        error: "Error al obtener los puntos de marcado",
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
      });
    }

    // Mejor manejo de respuesta cuando no hay resultados
    if (result.length === 0) {
      return res.status(200).json({
        success: true,
        message: "No se encontraron puntos de marcado para el vehículo y empresa especificados.",
        data: []
      });
    }

    // Respuesta exitosa
    res.json({
      success: true,
      data: result
    });
  });
});

// RUTA PARA CALCULAR DIFERENCIA DE HORAS AL MARCAR
app.post("/calcular-diferencia", async (req, res) => {
  try {
    const { hora_salida_turno, fkidturnohora, hora_marcado } = req.body;

    // 1. Obtener tiempo programado desde turno_horas
    const [turnoHora] = await db.promise().execute(
      `SELECT tiempo, fkidpunto, p.orden 
       FROM turno_horas th 
       JOIN puntos p ON th.fkidpunto = p.id
       WHERE th.id = ?`,
      [fkidturnohora]
    );

    if (turnoHora.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No se encontró la programación del punto"
      });
    }

    const { tiempo, fkidpunto, orden } = turnoHora[0];

    // 2. Calcular diferencia (¡CORRECCIÓN AQUÍ!)
    const [horas, minutos] = tiempo.split(':').map(Number);
    const totalMinutos = (horas * 60) + minutos;
    const horaEsperada = moment(hora_salida_turno).add(totalMinutos, 'minutes');
    const diferencia = moment(horaEsperada).diff(hora_marcado, 'minutes'); // ✅ horaEsperada - hora_marcado

    res.json({
      success: true,
      data: {
        diferencia_minutos: diferencia, // +n (adelanto) o -n (retraso)
        hora_esperada: horaEsperada.format('YYYY-MM-DD HH:mm:ss'),
        tiempo_programado: tiempo,
        idpunto: fkidpunto,
        orden_punto: orden,
        estado: diferencia >= 0 ? "A tiempo" : "Con retraso" // ✅ Cambia la condición
      }
    });

  } catch (error) {
    console.error("Error en /calcular-diferencia:", error);
    res.status(500).json({
      success: false,
      message: "Error en cálculo de diferencia"
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

    // 1. Verificar que el punto pertenece al turno
    const [puntoTurno] = await db.promise().execute(
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

    // 2. Validar distancia (30m máximo)
    const dentroDelRango = distancia <= 30;
    const mensaje = dentroDelRango 
      ? "Está dentro del rango permitido (15m)" 
      : `Está a ${distancia.toFixed(1)}m del punto (máximo 15m permitidos)`;

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
    const [turnoHora] = await db.promise().execute(
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

    // 2. Insertar marcación con valores por defecto
    const fechaMarcado = fecha || new Date().toISOString();
    const diferenciaCalculada = diferencia || 0;
    const celularInfo = celular || JSON.stringify({ deviceId });

    const [result] = await db.promise().execute(
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
    
    if (!idturno) {
      return res.status(400).json({
        success: false,
        message: "Se requiere el parámetro idturno"
      });
    }

    // Si db.execute() está fallando, intenta con db.query()
    db.query(`
      SELECT 
        p.id, p.nombre, p.latitud, p.longitud,
        th.id AS idTurnoHora, p.orden, th.tiempo
      FROM turno_horas th
      JOIN puntos p ON p.id = th.fkidpunto
      WHERE th.fkidturno = ?
      ORDER BY p.orden
    `, [idturno], (err, puntos) => {
      if (err) {
        console.error("Error en consulta SQL:", err);
        return res.status(500).json({
          success: false,
          message: "Error en la consulta de puntos"
        });
      }
      
      console.log("Puntos recuperados:", puntos.length);
      
      res.json({
        success: true,
        data: puntos
      });
    });
    
  } catch (error) {
    console.error("Error en /puntos-turno:", error);
    res.status(500).json({
      success: false,
      message: "Error al obtener puntos del turno"
    });
  }
});

// RUTA PARA OBTENER INCIDENTES POR TURNO
app.get("/incidentes_por_turno/:idTurno", async (req, res) => {
  try {
    const [incidentes] = await db.execute(
      `SELECT id, descripcion, hora, foto 
       FROM incidentes 
       WHERE fkidturno = ? 
       ORDER BY hora DESC`,
      [req.params.idTurno]
    );
    res.json({ success: true, data: incidentes });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error al obtener incidentes" });
  }
});

// RUTA PARA OMITIR PUNTO DE MARCADO
app.post("/omitir_punto", async (req, res) => {
  try {
    const { fk_idturno, fk_idpunto, fk_idincidente } = req.body;

    console.log("========== INICIANDO REGISTRO DE OMISIÓN ==========");
    console.log("Datos recibidos en req.body:", req.body);

    // Verificar que los datos requeridos estén presentes
    if (!fk_idturno || !fk_idpunto || !fk_idincidente) {
      console.warn("Faltan datos requeridos:", { fk_idturno, fk_idpunto, fk_idincidente });
      return res.status(400).json({
        success: false,
        message: "Faltan datos requeridos",
        datos_recibidos: { fk_idturno, fk_idpunto, fk_idincidente },
      });
    }

    console.log("Datos validados. Procediendo con la inserción...");

    const queryOmitirPunto = `
      INSERT INTO marcaciones (hora_marcado, longitud, latitud, diferencia, fk_idturno, fk_idpunto, fk_idincidente, omitido)
      VALUES (NOW(), NULL, NULL, NULL, ?, ?, ?, 1)
    `;

    console.log("Ejecutando consulta SQL...");
    console.log("Query:", queryOmitirPunto);
    console.log("Valores:", [fk_idturno, fk_idpunto]);

    const [result] = await db.promise().execute(queryOmitirPunto, [
      fk_idturno,
      fk_idpunto,
      fk_idincidente,
    ]);

    console.log("Resultado de la consulta:", result);

    if (result.affectedRows === 1) {
      console.log("✅ Omisión de punto registrada exitosamente.");
      return res.json({
        success: true,
        message: "Omisión de punto registrada exitosamente",
        idmarcacion: result.insertId,
      });
    } else {
      console.error("⚠️ Error: No se afectaron filas en la base de datos.");
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
  }
});

// Finalizar turno
app.post("/finalizar-turno", async (req, res) => {
  try {
    const { idTurno } = req.body;

    if (!idTurno) {
      return res.status(400).json({
        success: false,
        message: "Se requiere el ID del turno"
      });
    }

    // Actualizar estado del turno a FINALIZADO (4)
    await db.promise().execute(
      `UPDATE turnos SET fkidestadoturno = 4 WHERE id = ?`,
      [idTurno]
    );

    res.json({
      success: true,
      message: "Turno finalizado correctamente"
    });

  } catch (error) {
    console.error("Error al finalizar turno:", error);
    res.status(500).json({
      success: false,
      message: "Error al finalizar el turno"
    });
  }
});
// Ruta para la vista previa y descarga del historial de rrecorrido

// Endpoint para obtener vista previa
app.get("/vista-previa/:idturno", async (req, res) => {
  const { idturno } = req.params;
  console.log("Consultando vista previa para turno:", idturno);
  
  try {
      // 1. Información básica del turno (conductor y vehículo)
      const [infoTurno] = await db.promise().execute(
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

      // 2. Consulta para puntos marcados (de tu consulta original)
      const [puntosMarcados] = await db.promise().execute(
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

      // 3. Consulta para incidentes (simplificada según tus tablas)
      const [incidentes] = await db.promise().execute(
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

      // 4. Combinamos los resultados
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
    const [infoTurno] = await db.promise().execute(
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

    const [puntos] = await db.promise().execute(
      `SELECT ps.nombre AS punto_marcado, m.fecha AS hora_marcado,
              m.diferencia, m.latitud, m.longitud
       FROM marcados m
       JOIN turno_horas th ON th.id = m.fkidturnohora
       JOIN puntos ps ON ps.id = th.fkidpunto
       WHERE th.fkidturno = ?
       ORDER BY m.fecha`,
      [idturno]
    );

    const [incidentes] = await db.promise().execute(
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
    doc.addPage(); // Nueva página
    doc.fontSize(16).text("INCIDENTES", { underline: true });
    doc.moveDown(0.5);

    for (let i = 0; i < incidentes.length; i++) {
      const inc = incidentes[i];
      doc.fontSize(12).text(`${i + 1}. Hora: ${inc.hora_incidente}`);
      doc.text(`   Descripción: ${inc.descripcion_incidente}`);
      doc.text(`   Ubicación: [${inc.latitud}, ${inc.longitud}]`);

      // Ruta a imagen local (asegúrate que esta ruta es correcta)
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
