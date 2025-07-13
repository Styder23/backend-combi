require("dotenv").config();
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const router = express.Router();
const db = require("./../db");

// Configuración de Multer para guardar las imágenes
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath = "";

    // Determinar la carpeta de destino según el tipo de archivo
    if (file.fieldname === "foto_incidente") {
      uploadPath = "incidenteupload"; // Coincide con el path en server.js
    } else if (file.fieldname === "foto_perfil") {
      uploadPath = "perfilupload"; // Coincide con el path en server.js
    }

    // Crear la carpeta si no existe
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }

    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + ext);
  },
});

const upload = multer({ storage });

  // Endpoint para subir la foto de un incidente
  router.post("/reportar_incidente", upload.single("foto_incidente"), async (req, res) => {
    try {
      const { descripcion, latitud, longitud, fkidturno } = req.body;

      if (!descripcion || !latitud || !longitud || !fkidturno || !req.file) {
        return res.status(400).json({
          success: false,
          message: "Faltan datos requeridos",
        });
      }

      const rutaFoto = req.file.path.replace(/\\/g, '/'); // Normalizar ruta para BD

      const queryInsertIncidente = `
        INSERT INTO incidentes 
        (descripcion, latitud, longitud, hora, foto, fkidturno)
        VALUES (?, ?, ?, NOW(), ?, ?)
      `;

      const [result] = await db.execute(queryInsertIncidente, [
        descripcion,
        latitud,
        longitud,
        rutaFoto,
        fkidturno,
      ]);

      if (result.affectedRows === 1) {
        return res.json({
          success: true,
          message: "Incidente reportado exitosamente",
          idincidente: result.insertId,
          rutaFoto
        });
      } else {
        return res.status(500).json({
          success: false,
          message: "Error al reportar el incidente",
        });
      }
    } catch (error) {
      console.error("Error al reportar el incidente:", error);
      res.status(500).json({
        success: false,
        message: "Error interno del servidor",
        error: error.message
      });
    }
  });

// Endpoint para subir la foto de perfil
router.post("/subir_foto_perfil", upload.single("foto_perfil"), async (req, res) => {
  try {
    console.log("=== BACKEND DEBUG ===");
    console.log("Query params:", req.query);
    console.log("Body:", req.body);
    console.log("File:", req.file);
    
    const { id } = req.query;
    console.log("ID extraído:", id);

    if (!id || !req.file) {
      console.error("Faltan datos requeridos.", { id, file: !!req.file });
      return res.status(400).json({
        success: false,
        message: "Faltan datos requeridos",
      });
    }

    // Verificar si el usuario existe
    const [userResult] = await db.execute(
      "SELECT id FROM users WHERE id = ?",
      [id]
    );

    if (userResult.length === 0) {
      console.error("Usuario no encontrado.");
      return res.status(404).json({
        success: false,
        message: "Usuario no encontrado",
      });
    }

    // Guardar ruta normalizada en la base de datos
    const rutaFoto = req.file.path.replace(/\\/g, '/');

    const [updateResult] = await db.execute(
      "UPDATE users SET profile_photo_path = ? WHERE id = ?",
      [rutaFoto, id]
    );

    if (updateResult.affectedRows === 1) {
      console.log("Foto de perfil actualizada correctamente:", rutaFoto);
      return res.json({
        success: true,
        message: "Foto de perfil actualizada exitosamente",
        profile_photo_path: rutaFoto,
      });
    } else {
      console.error("No se pudo actualizar la foto.");
      return res.status(500).json({
        success: false,
        message: "Error al actualizar la foto de perfil",
      });
    }
  } catch (error) {
    console.error("Error en el backend:", error);
    return res.status(500).json({
      success: false,
      message: "Error interno del servidor",
      error: error.message,
    });
  }
});


module.exports = router;