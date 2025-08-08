// server.js - Main backend file
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");
const sharp = require("sharp");
const fs = require("fs");
const path = require("path");
const { PDFDocument } = require("pdf-lib");

require("dotenv").config();

// Initialize Express
const app = express();
app.use(express.json());
// Replace your current CORS setup with this simplest version
app.use(cors());

// Configure cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

cloudinary.api
  .ping()
  .then((result) => {
    console.log("Cloudinary is connected:", result);
  })
  .catch((error) => {
    console.error("Error connecting to Cloudinary:", error);
  });

// Configure MySQL connection
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "capstone_portal",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

pool
  .getConnection()
  .then((connection) => {
    console.log("Database connected successfully");
    connection.release();
  })
  .catch((err) => {
    console.error("Database connection error:", err);
  });

// Middleware for authentication
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res.status(401).json({ message: "Authentication required" });

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "your_jwt_secret"
    );

    // Get user from database to check approval status
    const [users] = await pool.execute(
      "SELECT id, username, role, is_approved FROM users WHERE id = ?",
      [decoded.id]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = users[0];

    // If user is not approved and not an admin, deny access except for approval status check
    if (
      !user.is_approved &&
      user.role !== "admin" &&
      !req.url.includes("/api/users/approval-status")
    ) {
      return res.status(403).json({
        message:
          "Your account is pending approval. Please contact an administrator.",
        pending_approval: true,
      });
    }

    req.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      is_approved: user.is_approved === 1,
    };
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

// Define allowed file types for each category
const allowedFileTypes = {
  problem_statement: ["application/pdf"],
  dataset: [
    "text/csv",
    "application/json",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain",
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream", // For .zip files that might be detected as this
  ],
  additional_resource: [
    "application/pdf",
    "text/plain",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/csv",
    "application/json",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/zip",
    "application/x-zip-compressed",
    "image/jpeg",
    "image/png",
    "image/gif",
    "application/octet-stream",
  ],
};

// Configure multer for file uploads with dynamic file filtering
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const fileType = req.params.fileType || "problem_statement"; // Get from URL params
    const allowedTypes =
      allowedFileTypes[fileType] || allowedFileTypes.problem_statement;

    console.log(`File type: ${fileType}, MIME type: ${file.mimetype}`);
    console.log(`Allowed types:`, allowedTypes);

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      const allowedExtensions = getFileExtensionsFromMimeTypes(allowedTypes);
      cb(
        new Error(
          `Only ${allowedExtensions.join(
            ", "
          )} files are allowed for ${fileType}`
        ),
        false
      );
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max file size for datasets and other files
});

// Helper function to get file extensions from MIME types
function getFileExtensionsFromMimeTypes(mimeTypes) {
  const mimeToExtension = {
    "application/pdf": "PDF",
    "text/csv": "CSV",
    "application/json": "JSON",
    "application/vnd.ms-excel": "XLS",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "XLSX",
    "text/plain": "TXT",
    "application/zip": "ZIP",
    "application/x-zip-compressed": "ZIP",
    "application/msword": "DOC",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
      "DOCX",
    "image/jpeg": "JPG",
    "image/png": "PNG",
    "image/gif": "GIF",
    "application/octet-stream": "Various",
  };

  return [...new Set(mimeTypes.map((type) => mimeToExtension[type] || type))];
}

// Compress PDF function (only for PDFs)
async function compressPDF(buffer, mimeType) {
  try {
    // Only compress PDFs
    if (mimeType !== "application/pdf") {
      const sizeInKB = buffer.length / 1024;
      return { buffer, sizeInKB, compressed: false };
    }

    // First check the size
    const sizeInKB = buffer.length / 1024;

    // If already below 100KB, return the original buffer
    if (sizeInKB <= 100) {
      return { buffer, sizeInKB, compressed: false };
    }

    // Try to compress using pdf-lib
    const pdfDoc = await PDFDocument.load(buffer);
    const pages = pdfDoc.getPages();

    // Compress using PDF quality settings
    const compressedPdfBytes = await pdfDoc.save({
      useObjectStreams: true,
      addCompressXref: true,
      objectsPerStream: 50,
    });

    const compressedSizeInKB = compressedPdfBytes.length / 1024;

    // For PDFs, if still above 200KB after compression, return null
    if (compressedSizeInKB > 200) {
      return { buffer: null, sizeInKB: compressedSizeInKB, compressed: true };
    }

    return {
      buffer: compressedPdfBytes,
      sizeInKB: compressedSizeInKB,
      compressed: true,
    };
  } catch (error) {
    console.error("PDF compression error:", error);
    return {
      buffer: null,
      sizeInKB: buffer.length / 1024,
      compressed: false,
      error,
    };
  }
}

// Add review for a submission (Updated - removed role restriction)
app.post(
  "/api/submissions/:submissionId/reviews",
  authenticateToken,
  async (req, res) => {
    try {
      const { submissionId } = req.params;
      const { rating, comments } = req.body;

      // Validate input
      if (!rating || rating < 1 || rating > 10) {
        return res.status(400).json({
          message: "Rating is required and must be between 1 and 10",
        });
      }

      if (!comments || comments.trim() === "") {
        return res.status(400).json({
          message: "Comments are required",
        });
      }

      // Check if submission exists
      const [submissions] = await pool.execute(
        "SELECT s.*, p.created_by FROM submissions s JOIN projects p ON s.project_id = p.id WHERE s.id = ?",
        [submissionId]
      );

      if (submissions.length === 0) {
        return res.status(404).json({ message: "Submission not found" });
      }

      const submission = submissions[0];

      // Check if both phases have been submitted for this student
      // const [phaseCount] = await pool.execute(
      //   "SELECT COUNT(*) as phases FROM submissions WHERE project_id = ? AND student_id = ?",
      //   [submission.project_id, submission.student_id]
      // );

      // if (phaseCount[0].phases < 2) {
      //   return res.status(400).json({
      //     message: "Cannot review until both phases have been submitted",
      //   });
      // }

      // Check if this user has already reviewed this submission
      const [existingReviews] = await pool.execute(
        "SELECT * FROM reviews WHERE submission_id = ? AND reviewer_id = ?",
        [submissionId, req.user.id]
      );

      if (existingReviews.length > 0) {
        return res.status(409).json({
          message: "You have already reviewed this submission",
        });
      }

      // Create the review
      const [reviewResult] = await pool.execute(
        "INSERT INTO reviews (submission_id, project_id, student_id, reviewer_id, reviewer_role, rating, comments) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          submissionId,
          submission.project_id,
          submission.student_id,
          req.user.id,
          req.user.role,
          rating,
          comments,
        ]
      );

      // Update submission status to "reviewed"
      await pool.execute(
        "UPDATE submissions SET status = 'reviewed' WHERE id = ?",
        [submissionId]
      );

      res.status(201).json({
        message: "Review submitted successfully",
        reviewId: reviewResult.insertId,
        reviewer: req.user.username,
        rating,
        comments,
      });
    } catch (error) {
      console.error("Review submission error:", error);
      res
        .status(500)
        .json({ message: "Failed to submit review", error: error.message });
    }
  }
);
// Get reviews for a submission
app.get(
  "/api/submissions/:submissionId/reviews",
  authenticateToken,
  async (req, res) => {
    try {
      const { submissionId } = req.params;

      // Get submission details to check permissions
      const [submissions] = await pool.execute(
        "SELECT s.*, p.created_by, p.state FROM submissions s JOIN projects p ON s.project_id = p.id WHERE s.id = ?",
        [submissionId]
      );

      if (submissions.length === 0) {
        return res.status(404).json({ message: "Submission not found" });
      }

      const submission = submissions[0];

      // Check permissions based on role and project state
      let hasAccess = false;

      // Students can only see reviews of their own submissions
      if (req.user.role === "student") {
        hasAccess = submission.student_id === req.user.id;
      }
      // Teachers can see reviews of submissions for projects they created or past projects
      else if (req.user.role === "teacher") {
        hasAccess =
          submission.created_by === req.user.id || submission.state === "past";
      }
      // Other authorized roles can see all reviews
      else if (
        [
          "evaluator",
          "admin",
          "coordinator",
          "manager",
          "academic_team",
        ].includes(req.user.role)
      ) {
        hasAccess = true;
      }

      if (!hasAccess) {
        return res.status(403).json({
          message: "You do not have permission to view these reviews",
        });
      }

      // Get all reviews for this submission
      const [reviews] = await pool.execute(
        `SELECT r.*, u.username as reviewer_name 
         FROM reviews r
         JOIN users u ON r.reviewer_id = u.id
         WHERE r.submission_id = ?
         ORDER BY r.created_at DESC`,
        [submissionId]
      );

      res.json({ reviews });
    } catch (error) {
      console.error("Error fetching reviews:", error);
      res
        .status(500)
        .json({ message: "Failed to fetch reviews", error: error.message });
    }
  }
);

// Get all students with any submissions for review (phase 1, phase 2, or both)
app.get(
  "/api/projects/:projectId/submissions-review",
  authenticateToken,
  async (req, res) => {
    try {
      const { projectId } = req.params;

      // Authorization check (same as before)
      if (
        ![
          "teacher",
          "academic_team",
          "evaluator",
          "admin",
          "manager",
          "coordinator",
        ].includes(req.user.role)
      ) {
        return res
          .status(403)
          .json({ message: "You do not have permission to view submissions" });
      }

      // First get project details to check state and ownership
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ?",
        [projectId]
      );

      if (projects.length === 0) {
        return res.status(404).json({ message: "Project not found" });
      }

      const project = projects[0];

      // Verify teacher ownership if applicable, but allow access to past projects
      if (req.user.role === "teacher") {
        if (project.created_by !== req.user.id && project.state !== "past") {
          return res.status(403).json({
            message: "You do not have permission to view these submissions",
          });
        }
      }

      // Get all students with any submissions and their phase details
      const [submissions] = await pool.execute(
        `SELECT 
          u.id AS student_id,
          u.username,
          u.email,
          s1.id AS phase1_submission_id,
          s1.file_url AS phase1_file_url,
          s1.submitted_at AS phase1_submitted_at,
          s1.status AS phase1_status,
          s2.id AS phase2_submission_id,
          s2.file_url AS phase2_file_url,
          s2.submitted_at AS phase2_submitted_at,
          s2.status AS phase2_status
        FROM users u
        LEFT JOIN submissions s1 ON u.id = s1.student_id AND s1.project_id = ? AND s1.phase = 1
        LEFT JOIN submissions s2 ON u.id = s2.student_id AND s2.project_id = ? AND s2.phase = 2
        WHERE EXISTS (
          SELECT 1 FROM submissions s
          WHERE s.student_id = u.id AND s.project_id = ?
        )
        ORDER BY u.username`,
        [projectId, projectId, projectId]
      );

      // Get review counts for each submission
      for (const student of submissions) {
        // Phase 1 reviews
        if (student.phase1_submission_id) {
          const [reviews] = await pool.execute(
            "SELECT COUNT(*) AS review_count FROM reviews WHERE submission_id = ?",
            [student.phase1_submission_id]
          );
          student.phase1_review_count = reviews[0].review_count;
        }

        // Phase 2 reviews
        if (student.phase2_submission_id) {
          const [reviews] = await pool.execute(
            "SELECT COUNT(*) AS review_count FROM reviews WHERE submission_id = ?",
            [student.phase2_submission_id]
          );
          student.phase2_review_count = reviews[0].review_count;
        }
      }

      res.json({
        submissions,
        project_state: project.state || "active",
      });
    } catch (error) {
      console.error("Error fetching submissions for review:", error);
      res.status(500).json({
        message: "Failed to fetch submissions",
        error: error.message,
      });
    }
  }
);
// Get students with both phases submitted (for review)
app.get(
  "/api/projects/:projectId/complete-submissions",
  authenticateToken,
  async (req, res) => {
    try {
      const { projectId } = req.params;

      // Check if user is authorized to view submissions
      if (
        ![
          "teacher",
          "academic_team",
          "evaluator",
          "admin",
          "manager",
          "coordinator",
        ].includes(req.user.role)
      ) {
        return res.status(403).json({
          message: "You do not have permission to view submissions",
        });
      }

      // If teacher, verify they created the project
      if (req.user.role === "teacher") {
        const [projects] = await pool.execute(
          "SELECT * FROM projects WHERE id = ? AND created_by = ?",
          [projectId, req.user.id]
        );

        if (projects.length === 0) {
          return res.status(403).json({
            message: "You do not have permission to view these submissions",
          });
        }
      }

      // Get students who have submitted both phases
      const [completeSubmissions] = await pool.execute(
        `SELECT 
          s1.student_id, 
          u.username, 
          u.email,
          s1.id as phase1_submission_id,
          s1.file_url as phase1_file_url,
          s1.submitted_at as phase1_submitted_at,
          s2.id as phase2_submission_id,
          s2.file_url as phase2_file_url,
          s2.submitted_at as phase2_submitted_at,
          s2.status
        FROM submissions s1
        JOIN submissions s2 ON s1.student_id = s2.student_id AND s1.project_id = s2.project_id
        JOIN users u ON s1.student_id = u.id
        WHERE s1.project_id = ? AND s1.phase = 1 AND s2.phase = 2
        ORDER BY s2.submitted_at DESC`,
        [projectId]
      );

      // Check which submissions have reviews
      for (let i = 0; i < completeSubmissions.length; i++) {
        const [reviews] = await pool.execute(
          `SELECT COUNT(*) as review_count FROM reviews 
           WHERE project_id = ? AND student_id = ?`,
          [projectId, completeSubmissions[i].student_id]
        );

        completeSubmissions[i].review_count = reviews[0].review_count;
        completeSubmissions[i].has_reviews = reviews[0].review_count > 0;
      }

      res.json({ completeSubmissions });
    } catch (error) {
      console.error("Error fetching complete submissions:", error);
      res.status(500).json({
        message: "Failed to fetch complete submissions",
        error: error.message,
      });
    }
  }
);

// Update a review
app.put("/api/reviews/:reviewId", authenticateToken, async (req, res) => {
  try {
    const { reviewId } = req.params;
    const { rating, comments } = req.body;

    // Validate input
    if (rating === undefined || rating < 1 || rating > 10) {
      return res
        .status(400)
        .json({ message: "Rating must be between 1 and 10" });
    }
    if (!comments || comments.trim() === "") {
      return res.status(400).json({ message: "Comments are required" });
    }

    // Check if review exists
    const [reviews] = await pool.execute("SELECT * FROM reviews WHERE id = ?", [
      reviewId,
    ]);
    if (reviews.length === 0) {
      return res.status(404).json({ message: "Review not found" });
    }
    const review = reviews[0];

    // Authorization check
    if (
      review.reviewer_id !== req.user.id &&
      !["admin", "academic_team", "coordinator"].includes(req.user.role)
    ) {
      return res
        .status(403)
        .json({ message: "Unauthorized to edit this review" });
    }

    // Update review
    await pool.execute(
      "UPDATE reviews SET rating = ?, comments = ? WHERE id = ?",
      [rating, comments, reviewId]
    );

    res.json({ message: "Review updated successfully" });
  } catch (error) {
    console.error("Error updating review:", error);
    res
      .status(500)
      .json({ message: "Failed to update review", error: error.message });
  }
});

// Delete a review
app.delete("/api/reviews/:reviewId", authenticateToken, async (req, res) => {
  try {
    const { reviewId } = req.params;

    // Check if review exists
    const [reviews] = await pool.execute("SELECT * FROM reviews WHERE id = ?", [
      reviewId,
    ]);
    if (reviews.length === 0) {
      return res.status(404).json({ message: "Review not found" });
    }
    const review = reviews[0];

    // Authorization check
    if (
      review.reviewer_id !== req.user.id &&
      !["admin", "academic_team", "coordinator"].includes(req.user.role)
    ) {
      return res
        .status(403)
        .json({ message: "Unauthorized to delete this review" });
    }

    // Delete review
    await pool.execute("DELETE FROM reviews WHERE id = ?", [reviewId]);

    res.json({ message: "Review deleted successfully" });
  } catch (error) {
    console.error("Error deleting review:", error);
    res
      .status(500)
      .json({ message: "Failed to delete review", error: error.message });
  }
});

app.get("/api/test", (req, res) => {
  console.log("Test endpoint hit!");
  const num = 9 * 7;
  res.json({ message: num });
});

// Upload project file (Updated to support multiple file types)
app.post(
  "/api/projects/:projectId/files/:fileType",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const { projectId, fileType } = req.params; // Get fileType from URL params
      // const { fileType } = req.body;

      console.log(`Uploading ${fileType} file to project ${projectId}`);
      console.log(`File details:`, {
        name: req.file.originalname,
        mimetype: req.file.mimetype,
        size: `${(req.file.size / 1024).toFixed(2)}KB`,
      });

      // Validate fileType
      if (
        !["problem_statement", "dataset", "additional_resource"].includes(
          fileType
        )
      ) {
        return res.status(400).json({ message: "Invalid file type" });
      }

      // Check if project exists
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ?",
        [projectId]
      );

      if (projects.length === 0) {
        return res.status(404).json({ message: "Project not found" });
      }

      let processedBuffer = req.file.buffer;
      let sizeInKB = req.file.size / 1024;
      let compressed = false;

      // Only compress PDFs and apply size restrictions for problem statements
      if (
        fileType === "problem_statement" &&
        req.file.mimetype === "application/pdf"
      ) {
        const compressionResult = await compressPDF(
          req.file.buffer,
          req.file.mimetype
        );

        if (!compressionResult.buffer) {
          return res.status(400).json({
            message:
              "PDF file too large even after compression. Must be under 200KB when compressed.",
            originalSize: `${compressionResult.sizeInKB.toFixed(2)}KB`,
            compressed: compressionResult.compressed,
          });
        }

        processedBuffer = compressionResult.buffer;
        sizeInKB = compressionResult.sizeInKB;
        compressed = compressionResult.compressed;
      }

      // For non-PDF files, check reasonable size limits
      const maxSizes = {
        problem_statement: 200, // 200KB for PDFs
        dataset: 50 * 1024, // 50MB for datasets
        additional_resource: 20 * 1024, // 20MB for additional resources
      };

      if (sizeInKB > maxSizes[fileType]) {
        return res.status(400).json({
          message: `File too large. Maximum size for ${fileType} is ${
            maxSizes[fileType] > 1024
              ? (maxSizes[fileType] / 1024).toFixed(0) + "MB"
              : maxSizes[fileType] + "KB"
          }`,
          currentSize: `${
            sizeInKB > 1024
              ? (sizeInKB / 1024).toFixed(2) + "MB"
              : sizeInKB.toFixed(2) + "KB"
          }`,
        });
      }

      // Upload to Cloudinary
      return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: "capstone_projects",
            resource_type: "raw",
            public_id: `project_${projectId}_${fileType}_${Date.now()}`,
          },
          async (error, result) => {
            if (error) {
              console.error("Cloudinary upload error:", error);
              return res.status(500).json({
                message: "Failed to upload file",
                error: error.message,
              });
            }

            try {
              const [fileResult] = await pool.execute(
                "INSERT INTO project_files (project_id, file_name, file_url, file_type, uploaded_by) VALUES (?, ?, ?, ?, ?)",
                [
                  projectId,
                  req.file.originalname,
                  result.secure_url,
                  fileType,
                  req.user.id,
                ]
              );

              res.status(201).json({
                message: compressed
                  ? "File compressed and uploaded successfully"
                  : "File uploaded successfully",
                fileId: fileResult.insertId,
                fileName: req.file.originalname,
                fileUrl: result.secure_url,
                fileType,
                size:
                  sizeInKB > 1024
                    ? `${(sizeInKB / 1024).toFixed(2)}MB`
                    : `${sizeInKB.toFixed(2)}KB`,
                compressed,
              });
            } catch (dbError) {
              console.error("Database error:", dbError);
              res.status(500).json({
                message: "Failed to save file info",
                error: dbError.message,
              });
            }
          }
        );

        streamifier.createReadStream(processedBuffer).pipe(uploadStream);
      });
    } catch (error) {
      console.error("File upload error:", error);
      res
        .status(500)
        .json({ message: "File upload failed", error: error.message });
    }
  }
);

app.post("/api/projects", authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      accessRoles = [],
      firstDeadline,
      finalDeadline,
    } = req.body;

    if (!firstDeadline || !finalDeadline) {
      return res
        .status(400)
        .json({ message: "Both deadlines must be provided" });
    }

    const firstDeadlineDate = new Date(firstDeadline);
    const finalDeadlineDate = new Date(finalDeadline);

    if (firstDeadlineDate >= finalDeadlineDate) {
      return res
        .status(400)
        .json({ message: "First deadline must be before final deadline" });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Create project with pending status for manager approval
      const [project] = await connection.execute(
        "INSERT INTO projects (title, description, created_by, first_deadline, final_deadline, status) VALUES (?, ?, ?, ?, ?, ?)",
        [
          title,
          description,
          req.user.id,
          firstDeadlineDate,
          finalDeadlineDate,
          "pending_approval",
        ]
      );

      const projectId = project.insertId;

      await connection.commit();

      res.status(201).json({
        message: "Project created successfully and sent for manager approval",
        projectId,
        status: "pending_approval",
        project: {
          id: projectId,
          title,
          description,
          created_by: req.user.id,
          first_deadline: firstDeadline,
          final_deadline: finalDeadline,
          status: "pending_approval",
        },
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Project creation error:", error);
    res
      .status(500)
      .json({ message: "Failed to create project", error: error.message });
  }
});

// Get project details for any user based on role
app.get("/api/projects/:projectId", authenticateToken, async (req, res) => {
  try {
    const { projectId } = req.params;

    // Check if user has access to this project
    let hasAccess = false;

    if (req.user.role === "teacher") {
      // Teachers can access projects they created
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ? AND created_by = ?",
        [projectId, req.user.id]
      );
      hasAccess = projects.length > 0;
    } else {
    }

    // Get project details
    const [projects] = await pool.execute(
      "SELECT * FROM projects WHERE id = ?",
      [projectId]
    );

    if (projects.length === 0) {
      return res.status(404).json({ message: "Project not found" });
    }

    const project = projects[0];

    // Get files
    const [files] = await pool.execute(
      "SELECT * FROM project_files WHERE project_id = ?",
      [projectId]
    );
    project.files = files;

    // Get submissions (if teacher or appropriate role)
    if (
      [
        "teacher",
        "academic_team",
        "evaluator",
        "manager",
        "coordinator",
        "admin",
      ].includes(req.user.role)
    ) {
      // Get phase 1 submissions
      const [phase1Submissions] = await pool.execute(
        `SELECT s.*, u.username FROM submissions s
         INNER JOIN users u ON s.student_id = u.id
         WHERE s.project_id = ? AND s.phase = 1`,
        [projectId]
      );
      project.phase1Submissions = phase1Submissions;

      // Get phase 2 submissions
      const [phase2Submissions] = await pool.execute(
        `SELECT s.*, u.username FROM submissions s
         INNER JOIN users u ON s.student_id = u.id
         WHERE s.project_id = ? AND s.phase = 2`,
        [projectId]
      );
      project.phase2Submissions = phase2Submissions;

      // Get list of students who completed both phases
      const [completeSubmissions] = await pool.execute(
        `SELECT s1.student_id, u.username, u.email 
         FROM submissions s1
         JOIN submissions s2 ON s1.student_id = s2.student_id AND s1.project_id = s2.project_id
         JOIN users u ON s1.student_id = u.id
         WHERE s1.project_id = ? AND s1.phase = 1 AND s2.phase = 2`,
        [projectId]
      );
      project.completeSubmissions = completeSubmissions;

      // Get reviews for this project
      const [reviews] = await pool.execute(
        `SELECT r.*, 
         s.phase as submission_phase,
         u1.username as student_name, 
         u2.username as reviewer_name
         FROM reviews r
         JOIN submissions s ON r.submission_id = s.id
         JOIN users u1 ON r.student_id = u1.id
         JOIN users u2 ON r.reviewer_id = u2.id
         WHERE r.project_id = ?
         ORDER BY r.created_at DESC`,
        [projectId]
      );
      project.reviews = reviews;
    } else if (req.user.role === "student") {
      // Students can only see their own submissions
      const [phase1Submissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 1",
        [projectId, req.user.id]
      );
      project.phase1Submission =
        phase1Submissions.length > 0 ? phase1Submissions[0] : null;

      const [phase2Submissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 2",
        [projectId, req.user.id]
      );
      project.phase2Submission =
        phase2Submissions.length > 0 ? phase2Submissions[0] : null;

      // Get reviews for this student's submissions for this project
      if (phase1Submissions.length > 0 && phase2Submissions.length > 0) {
        const [reviews] = await pool.execute(
          `SELECT r.*, u.username as reviewer_name 
           FROM reviews r
           JOIN users u ON r.reviewer_id = u.id
           WHERE r.project_id = ? AND r.student_id = ?
           ORDER BY r.created_at DESC`,
          [projectId, req.user.id]
        );
        project.reviews = reviews;
      }
    }

    // Add deadline status for all users
    const currentDate = new Date();
    const firstDeadline = new Date(project.first_deadline);
    const finalDeadline = new Date(project.final_deadline);

    project.phase1DeadlinePassed = currentDate > firstDeadline;
    project.phase2DeadlinePassed = currentDate > finalDeadline;

    res.json({ project });
  } catch (error) {
    console.error("Error fetching project details:", error);
    res.status(500).json({
      message: "Failed to fetch project details",
      error: error.message,
    });
  }
});

// Get all students with their project access (Remove manager role check)
app.get(
  "/api/manager/students-with-access",
  authenticateToken,
  async (req, res) => {
    try {
      const [students] = await pool.execute(`
      SELECT 
        u.id AS student_id,
        u.username,
        u.email,
        spa.project_id,
        p.title AS project_title,
        p.status AS project_status,
        spa.approved_by,
        spa.approved_at,
        u2.username AS approved_by_username
      FROM users u
      LEFT JOIN student_project_access spa ON u.id = spa.student_id
      LEFT JOIN projects p ON spa.project_id = p.id
      LEFT JOIN users u2 ON spa.approved_by = u2.id
      WHERE u.role = 'student'
      ORDER BY u.username, p.title
    `);

      const studentMap = new Map();
      students.forEach((row) => {
        const studentId = row.student_id;
        if (!studentMap.has(studentId)) {
          studentMap.set(studentId, {
            id: studentId,
            username: row.username,
            email: row.email,
            projects: [],
          });
        }
        if (row.project_id) {
          studentMap.get(studentId).projects.push({
            project_id: row.project_id,
            title: row.project_title,
            status: row.project_status,
            approved_by: row.approved_by,
            approved_by_username: row.approved_by_username,
            approved_at: row.approved_at,
          });
        }
      });

      const studentsWithAccess = Array.from(studentMap.values());
      res.json({ students: studentsWithAccess });
    } catch (error) {
      console.error("Error fetching students with access:", error);
      res.status(500).json({
        message: "Failed to fetch student access data",
        error: error.message,
      });
    }
  }
);

// Grant project access to a student (Remove manager role check)
app.post(
  "/api/manager/students/:studentId/projects/:projectId",
  authenticateToken,
  async (req, res) => {
    const { studentId, projectId } = req.params;

    try {
      // Validate student exists and is a student
      const [students] = await pool.execute(
        "SELECT id FROM users WHERE id = ? AND role = 'student'",
        [studentId]
      );
      if (students.length === 0) {
        return res.status(404).json({ message: "Student not found" });
      }

      // Validate project exists (remove status check to allow access to all projects)
      const [projects] = await pool.execute(
        "SELECT id, title FROM projects WHERE id = ?",
        [projectId]
      );
      if (projects.length === 0) {
        return res.status(404).json({ message: "Project not found" });
      }

      // Check for existing access
      const [existingAccess] = await pool.execute(
        "SELECT * FROM student_project_access WHERE student_id = ? AND project_id = ?",
        [studentId, projectId]
      );
      if (existingAccess.length > 0) {
        return res.status(409).json({
          message: "Student already has access to this project",
          accessDetails: existingAccess[0],
        });
      }

      // Grant access
      await pool.execute(
        "INSERT INTO student_project_access (project_id, student_id, approved_by) VALUES (?, ?, ?)",
        [projectId, studentId, req.user.id]
      );

      res.status(201).json({
        message: "Access granted successfully",
        studentId: parseInt(studentId),
        projectId: parseInt(projectId),
        projectTitle: projects[0].title,
        approvedBy: req.user.id,
        approvedByUsername: req.user.username,
      });
    } catch (error) {
      console.error("Error granting access:", error);
      res.status(500).json({
        message: "Failed to grant access",
        error: error.message,
      });
    }
  }
);

// Remove project access from a student (Remove manager role check)
app.delete(
  "/api/manager/students/:studentId/projects/:projectId",
  authenticateToken,
  async (req, res) => {
    const { studentId, projectId } = req.params;

    try {
      // Validate access record exists
      const [existingAccess] = await pool.execute(
        "SELECT spa.*, p.title FROM student_project_access spa JOIN projects p ON spa.project_id = p.id WHERE spa.student_id = ? AND spa.project_id = ?",
        [studentId, projectId]
      );
      if (existingAccess.length === 0) {
        return res.status(404).json({ message: "Access record not found" });
      }

      // Remove access
      await pool.execute(
        "DELETE FROM student_project_access WHERE student_id = ? AND project_id = ?",
        [studentId, projectId]
      );

      res.json({
        message: "Access removed successfully",
        studentId: parseInt(studentId),
        projectId: parseInt(projectId),
        projectTitle: existingAccess[0].title,
        removedBy: req.user.username,
      });
    } catch (error) {
      console.error("Error removing access:", error);
      res.status(500).json({
        message: "Failed to remove access",
        error: error.message,
      });
    }
  }
);

// Get all students for project access management (Remove manager role check)
app.get("/api/manager/students", authenticateToken, async (req, res) => {
  try {
    const [students] = await pool.execute(
      "SELECT id, username, email, created_at FROM users WHERE role = 'student' ORDER BY username"
    );

    res.json({ students });
  } catch (error) {
    console.error("Error fetching students:", error);
    res.status(500).json({
      message: "Failed to fetch students",
      error: error.message,
    });
  }
});

// Get pending projects for approval (Remove manager role check)
app.get(
  "/api/manager/pending-projects",
  authenticateToken,
  async (req, res) => {
    try {
      const [projects] = await pool.execute(
        `SELECT p.*, u.username as creator_name 
       FROM projects p 
       JOIN users u ON p.created_by = u.id 
       WHERE p.status = 'pending_approval' 
       ORDER BY p.created_at DESC`
      );

      res.json({ projects });
    } catch (error) {
      console.error("Error fetching pending projects:", error);
      res.status(500).json({
        message: "Failed to fetch pending projects",
        error: error.message,
      });
    }
  }
);

// Approve project and students (Remove manager role check)
app.post(
  "/api/manager/approve-project",
  authenticateToken,
  async (req, res) => {
    try {
      const { projectId, approvedStudentIds = [] } = req.body;

      if (!projectId) {
        return res.status(400).json({ message: "Project ID is required" });
      }

      const connection = await pool.getConnection();
      await connection.beginTransaction();

      try {
        // Check if project exists and is pending
        const [projects] = await connection.execute(
          "SELECT * FROM projects WHERE id = ? AND status = 'pending_approval'",
          [projectId]
        );

        if (projects.length === 0) {
          await connection.rollback();
          return res.status(404).json({
            message: "Project not found or already processed",
          });
        }

        // Update project status to approved
        await connection.execute(
          "UPDATE projects SET status = 'approved', approved_by = ?, approved_at = NOW() WHERE id = ?",
          [req.user.id, projectId]
        );

        // Create student project access records for approved students
        let approvedCount = 0;
        for (const studentId of approvedStudentIds) {
          // Validate student exists
          const [student] = await connection.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'student'",
            [studentId]
          );

          if (student.length > 0) {
            await connection.execute(
              "INSERT INTO student_project_access (project_id, student_id, approved_by, approved_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE approved_by = ?, approved_at = NOW()",
              [projectId, studentId, req.user.id, req.user.id]
            );
            approvedCount++;
          }
        }

        await connection.commit();

        res.json({
          message: "Project approved successfully",
          projectId: parseInt(projectId),
          approvedStudentCount: approvedCount,
          approvedBy: req.user.username,
          approvedAt: new Date().toISOString(),
        });
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error("Project approval error:", error);
      res.status(500).json({
        message: "Failed to approve project",
        error: error.message,
      });
    }
  }
);

// Get project access details for a specific student (Remove manager role check)
app.get(
  "/api/manager/students/:studentId/projects",
  authenticateToken,
  async (req, res) => {
    const { studentId } = req.params;

    try {
      // Validate student exists
      const [students] = await pool.execute(
        "SELECT id, username, email FROM users WHERE id = ? AND role = 'student'",
        [studentId]
      );

      if (students.length === 0) {
        return res.status(404).json({ message: "Student not found" });
      }

      // Get all projects this student has access to
      const [accessibleProjects] = await pool.execute(
        `SELECT p.*, spa.approved_by, spa.approved_at, u.username as approved_by_username
       FROM student_project_access spa
       JOIN projects p ON spa.project_id = p.id
       JOIN users u ON spa.approved_by = u.id
       WHERE spa.student_id = ?
       ORDER BY p.created_at DESC`,
        [studentId]
      );

      // Get all projects this student does NOT have access to
      const [inaccessibleProjects] = await pool.execute(
        `SELECT p.* FROM projects p
       WHERE p.id NOT IN (
         SELECT project_id FROM student_project_access WHERE student_id = ?
       )
       ORDER BY p.created_at DESC`,
        [studentId]
      );

      res.json({
        student: students[0],
        accessibleProjects,
        inaccessibleProjects,
        totalAccessibleProjects: accessibleProjects.length,
        totalInaccessibleProjects: inaccessibleProjects.length,
      });
    } catch (error) {
      console.error("Error fetching student project access:", error);
      res.status(500).json({
        message: "Failed to fetch student project access",
        error: error.message,
      });
    }
  }
);

// Bulk grant access to multiple students for a project (Remove manager role check)
app.post(
  "/api/manager/projects/:projectId/grant-access",
  authenticateToken,
  async (req, res) => {
    const { projectId } = req.params;
    const { studentIds = [] } = req.body;

    if (!Array.isArray(studentIds) || studentIds.length === 0) {
      return res.status(400).json({ message: "Student IDs array is required" });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Validate project exists
      const [projects] = await connection.execute(
        "SELECT id, title FROM projects WHERE id = ?",
        [projectId]
      );

      if (projects.length === 0) {
        await connection.rollback();
        return res.status(404).json({ message: "Project not found" });
      }

      let successCount = 0;
      let errorCount = 0;
      const results = [];

      for (const studentId of studentIds) {
        try {
          // Validate student exists
          const [students] = await connection.execute(
            "SELECT id, username FROM users WHERE id = ? AND role = 'student'",
            [studentId]
          );

          if (students.length === 0) {
            results.push({
              studentId,
              status: "error",
              message: "Student not found",
            });
            errorCount++;
            continue;
          }

          // Check for existing access
          const [existingAccess] = await connection.execute(
            "SELECT * FROM student_project_access WHERE student_id = ? AND project_id = ?",
            [studentId, projectId]
          );

          if (existingAccess.length > 0) {
            results.push({
              studentId,
              username: students[0].username,
              status: "skipped",
              message: "Already has access",
            });
            continue;
          }

          // Grant access
          await connection.execute(
            "INSERT INTO student_project_access (project_id, student_id, approved_by) VALUES (?, ?, ?)",
            [projectId, studentId, req.user.id]
          );

          results.push({
            studentId,
            username: students[0].username,
            status: "success",
            message: "Access granted",
          });
          successCount++;
        } catch (error) {
          results.push({
            studentId,
            status: "error",
            message: error.message,
          });
          errorCount++;
        }
      }

      await connection.commit();

      res.json({
        message: "Bulk access grant completed",
        projectId: parseInt(projectId),
        projectTitle: projects[0].title,
        totalProcessed: studentIds.length,
        successCount,
        errorCount,
        results,
        grantedBy: req.user.username,
      });
    } catch (error) {
      await connection.rollback();
      console.error("Error in bulk grant access:", error);
      res.status(500).json({
        message: "Failed to grant bulk access",
        error: error.message,
      });
    } finally {
      connection.release();
    }
  }
);

// Get access summary for all projects (Remove manager role check)
app.get("/api/manager/access-summary", authenticateToken, async (req, res) => {
  try {
    const [summary] = await pool.execute(`
      SELECT 
        p.id as project_id,
        p.title,
        p.status,
        p.created_at,
        COUNT(spa.student_id) as students_with_access,
        (SELECT COUNT(*) FROM users WHERE role = 'student') as total_students
      FROM projects p
      LEFT JOIN student_project_access spa ON p.id = spa.project_id
      GROUP BY p.id, p.title, p.status, p.created_at
      ORDER BY p.created_at DESC
    `);

    // Get overall statistics
    const [overallStats] = await pool.execute(`
      SELECT 
        COUNT(DISTINCT p.id) as total_projects,
        COUNT(DISTINCT spa.student_id) as students_with_any_access,
        COUNT(DISTINCT CASE WHEN p.status = 'approved' THEN p.id END) as approved_projects,
        COUNT(DISTINCT CASE WHEN p.status = 'pending_approval' THEN p.id END) as pending_projects,
        (SELECT COUNT(*) FROM users WHERE role = 'student') as total_students
      FROM projects p
      LEFT JOIN student_project_access spa ON p.id = spa.project_id
    `);

    res.json({
      projectSummary: summary,
      overallStats: overallStats[0],
    });
  } catch (error) {
    console.error("Error fetching access summary:", error);
    res.status(500).json({
      message: "Failed to fetch access summary",
      error: error.message,
    });
  }
});

// User Registration
app.post("/api/register", async (req, res) => {
  console.log("Registration request received:", req.body);
  try {
    const { username, password, email, role } = req.body;

    // Validate role
    const validRoles = [
      "student",
      "teacher",
      "academic_team",
      "evaluator",
      "manager",
      "coordinator",
      "admin",
    ];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into database
    const [result] = await pool.execute(
      "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
      [username, hashedPassword, email, role]
    );

    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId,
    });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ message: "Username or email already exists" });
    }
    console.error("Registration error:", error);
    res
      .status(500)
      .json({ message: "Registration failed", error: error.message });
  }
});

// User Login
app.post("/api/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    if (!usernameOrEmail || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Find user by either username or email
    const [users] = await pool.execute(
      "SELECT * FROM users WHERE username = ? OR email = ?",
      [usernameOrEmail, usernameOrEmail]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = users[0];

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate JWT token with user ID
    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || "your_jwt_secret",
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_approved: user.is_approved === 1,
      },
      pending_approval: user.is_approved === 0 && user.role !== "admin",
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login failed", error: error.message });
  }
});

// Add this endpoint to your server.js file after the login endpoint

// Forgot Password - Reset password with email and new password
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and new password are required",
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        message: "Please provide a valid email address",
      });
    }

    // Validate password strength (optional - adjust as needed)
    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters long",
      });
    }

    // Check if user exists with this email
    const [users] = await pool.execute(
      "SELECT id, username, email FROM users WHERE email = ?",
      [email]
    );

    if (users.length === 0) {
      return res.status(404).json({
        message: "No user found with this email address",
      });
    }

    const user = users[0];

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the password in database
    await pool.execute("UPDATE users SET password = ? WHERE email = ?", [
      hashedPassword,
      email,
    ]);

    // Log the password reset for security purposes (optional)
    console.log(
      `Password reset for user: ${
        user.username
      } (${email}) at ${new Date().toISOString()}`
    );

    res.json({
      message: "Password reset successfully",
      username: user.username,
      email: user.email,
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({
      message: "Password reset failed",
      error: error.message,
    });
  }
});

// Updated Manager API endpoints - Remove role restrictions from these endpoints

// Phase 1 submission (Updated - check manager approval)
app.post(
  "/api/projects/:projectId/submissions/phase1",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const { projectId } = req.params;

      // Check if project exists and is approved
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ? AND status = 'approved'",
        [projectId]
      );

      if (projects.length === 0) {
        return res.status(404).json({
          message: "Project not found or not approved yet",
        });
      }

      // For students, check if they have access to this project
      if (req.user.role === "student") {
        const [access] = await pool.execute(
          "SELECT * FROM student_project_access WHERE project_id = ? AND student_id = ?",
          [projectId, req.user.id]
        );

        if (access.length === 0) {
          return res.status(403).json({
            message:
              "You are not approved to submit to this project. Contact your manager.",
          });
        }
      }

      const project = projects[0];
      const currentDate = new Date();
      const firstDeadline = new Date(project.first_deadline);

      if (currentDate > firstDeadline) {
        return res.status(400).json({
          message: "First phase submission deadline has passed",
          deadline: firstDeadline,
        });
      }

      // Check if user has already submitted phase 1
      const [existingSubmissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 1",
        [projectId, req.user.id]
      );

      if (existingSubmissions.length > 0) {
        return res.status(409).json({
          message: "You have already submitted phase 1 for this project",
        });
      }

      // Process and upload the PDF file
      const pdfBuffer = req.file.buffer;
      const {
        buffer: processedBuffer,
        sizeInKB,
        compressed,
      } = await compressPDF(pdfBuffer);

      if (!processedBuffer) {
        return res.status(400).json({
          message:
            "File too large even after compression. Must be under 200KB when compressed.",
          originalSize: `${sizeInKB.toFixed(2)}KB`,
          compressed,
        });
      }

      // Upload to Cloudinary
      return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: "capstone_submissions",
            resource_type: "raw",
            public_id: `submission_phase1_${projectId}_${
              req.user.id
            }_${Date.now()}`,
          },
          async (error, result) => {
            if (error) {
              console.error("Cloudinary upload error:", error);
              return res.status(500).json({
                message: "Failed to upload submission",
                error: error.message,
              });
            }

            try {
              const [submissionResult] = await pool.execute(
                "INSERT INTO submissions (project_id, student_id, file_name, file_url, phase, status) VALUES (?, ?, ?, ?, ?, ?)",
                [
                  projectId,
                  req.user.id,
                  req.file.originalname,
                  result.secure_url,
                  1,
                  "pending_phase2",
                ]
              );

              res.status(201).json({
                message: compressed
                  ? "Phase 1 submission compressed and uploaded successfully"
                  : "Phase 1 submission uploaded successfully",
                submissionId: submissionResult.insertId,
                fileName: req.file.originalname,
                fileUrl: result.secure_url,
                phase: 1,
                status: "pending_phase2",
                size: `${sizeInKB.toFixed(2)}KB`,
              });
            } catch (dbError) {
              console.error("Database error:", dbError);
              res.status(500).json({
                message: "Failed to save submission info",
                error: dbError.message,
              });
            }
          }
        );

        streamifier.createReadStream(processedBuffer).pipe(uploadStream);
      });
    } catch (error) {
      console.error("Submission error:", error);
      res
        .status(500)
        .json({ message: "Submission failed", error: error.message });
    }
  }
);
// Phase 2 submission (Updated - check manager approval)
app.post(
  "/api/projects/:projectId/submissions/phase2",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const { projectId } = req.params;

      // Check if project exists and is approved
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ? AND status = 'approved'",
        [projectId]
      );

      if (projects.length === 0) {
        return res.status(404).json({
          message: "Project not found or not approved yet",
        });
      }

      // For students, check if they have access to this project
      if (req.user.role === "student") {
        const [access] = await pool.execute(
          "SELECT * FROM student_project_access WHERE project_id = ? AND student_id = ?",
          [projectId, req.user.id]
        );

        if (access.length === 0) {
          return res.status(403).json({
            message:
              "You are not approved to submit to this project. Contact your manager.",
          });
        }
      }

      const project = projects[0];
      const currentDate = new Date();
      const finalDeadline = new Date(project.final_deadline);

      if (currentDate > finalDeadline) {
        return res.status(400).json({
          message: "Final phase submission deadline has passed",
          deadline: finalDeadline,
        });
      }

      // Check if user has already submitted phase 1 (required before phase 2)
      const [phase1Submissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 1",
        [projectId, req.user.id]
      );

      if (phase1Submissions.length === 0) {
        return res.status(400).json({
          message: "You must submit phase 1 before submitting phase 2",
        });
      }

      // Check if user has already submitted phase 2
      const [existingSubmissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 2",
        [projectId, req.user.id]
      );

      if (existingSubmissions.length > 0) {
        return res.status(409).json({
          message: "You have already submitted phase 2 for this project",
        });
      }

      // Process and upload the PDF file
      const pdfBuffer = req.file.buffer;
      const {
        buffer: processedBuffer,
        sizeInKB,
        compressed,
      } = await compressPDF(pdfBuffer);

      if (!processedBuffer) {
        return res.status(400).json({
          message:
            "File too large even after compression. Must be under 200KB when compressed.",
          originalSize: `${sizeInKB.toFixed(2)}KB`,
          compressed,
        });
      }

      // Upload to Cloudinary
      return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: "capstone_submissions",
            resource_type: "raw",
            public_id: `submission_phase2_${projectId}_${
              req.user.id
            }_${Date.now()}`,
          },
          async (error, result) => {
            if (error) {
              console.error("Cloudinary upload error:", error);
              return res.status(500).json({
                message: "Failed to upload submission",
                error: error.message,
              });
            }

            try {
              const [submissionResult] = await pool.execute(
                "INSERT INTO submissions (project_id, student_id, file_name, file_url, phase, status) VALUES (?, ?, ?, ?, ?, ?)",
                [
                  projectId,
                  req.user.id,
                  req.file.originalname,
                  result.secure_url,
                  2,
                  "submitted",
                ]
              );

              // Update phase 1 submission status to "completed"
              await pool.execute(
                "UPDATE submissions SET status = 'completed' WHERE project_id = ? AND student_id = ? AND phase = 1",
                [projectId, req.user.id]
              );

              res.status(201).json({
                message: compressed
                  ? "Phase 2 submission compressed and uploaded successfully"
                  : "Phase 2 submission uploaded successfully",
                submissionId: submissionResult.insertId,
                fileName: req.file.originalname,
                fileUrl: result.secure_url,
                phase: 2,
                status: "submitted",
                size: `${sizeInKB.toFixed(2)}KB`,
              });
            } catch (dbError) {
              console.error("Database error:", dbError);
              res.status(500).json({
                message: "Failed to save submission info",
                error: dbError.message,
              });
            }
          }
        );

        streamifier.createReadStream(processedBuffer).pipe(uploadStream);
      });
    } catch (error) {
      console.error("Submission error:", error);
      res
        .status(500)
        .json({ message: "Submission failed", error: error.message });
    }
  }
);

// Get student projects (Updated - check manager approval)
app.get("/api/student/projects", authenticateToken, async (req, res) => {
  try {
    // Get projects that are approved and student has access to
    let query = `SELECT p.* FROM projects p WHERE p.status = 'approved'`;
    let queryParams = [];

    if (req.user.role === "student") {
      query += ` AND EXISTS (SELECT 1 FROM student_project_access spa WHERE spa.project_id = p.id AND spa.student_id = ?)`;
      queryParams.push(req.user.id);
    }

    query += ` ORDER BY p.created_at DESC`;

    const [projects] = await pool.execute(query, queryParams);

    // Get files and submission status for each project
    for (let i = 0; i < projects.length; i++) {
      const [files] = await pool.execute(
        "SELECT * FROM project_files WHERE project_id = ?",
        [projects[i].id]
      );
      projects[i].files = files;

      // Check phase 1 submission status
      const [phase1Submissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 1",
        [projects[i].id, req.user.id]
      );
      projects[i].hasSubmittedPhase1 = phase1Submissions.length > 0;
      if (phase1Submissions.length > 0) {
        projects[i].phase1Submission = phase1Submissions[0];
      }

      // Check phase 2 submission status
      const [phase2Submissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 2",
        [projects[i].id, req.user.id]
      );
      projects[i].hasSubmittedPhase2 = phase2Submissions.length > 0;
      if (phase2Submissions.length > 0) {
        projects[i].phase2Submission = phase2Submissions[0];
      }

      // Get reviews for this student's submissions if both phases are submitted
      if (projects[i].hasSubmittedPhase1 && projects[i].hasSubmittedPhase2) {
        const [reviews] = await pool.execute(
          `SELECT r.*, u.username as reviewer_name 
           FROM reviews r
           JOIN users u ON r.reviewer_id = u.id
           WHERE r.project_id = ? AND r.student_id = ?
           ORDER BY r.created_at DESC`,
          [projects[i].id, req.user.id]
        );
        projects[i].reviews = reviews;
      }

      // Add deadline status
      const currentDate = new Date();
      const firstDeadline = new Date(projects[i].first_deadline);
      const finalDeadline = new Date(projects[i].final_deadline);

      projects[i].phase1DeadlinePassed = currentDate > firstDeadline;
      projects[i].phase2DeadlinePassed = currentDate > finalDeadline;
    }

    res.json({ projects });
  } catch (error) {
    console.error("Error fetching student projects:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch projects", error: error.message });
  }
});

// Get projects for teacher
app.get("/api/teacher/projects", authenticateToken, async (req, res) => {
  try {
    // Get all projects created by this teacher
    const [projects] = await pool.execute(
      "SELECT * FROM projects ORDER BY created_at DESC",
      [req.user.id]
    );

    // Get files for each project
    for (let i = 0; i < projects.length; i++) {
      const [files] = await pool.execute(
        "SELECT * FROM project_files WHERE project_id = ?",
        [projects[i].id]
      );
      projects[i].files = files;

      // Get submission counts for each phase
      const [phase1Count] = await pool.execute(
        "SELECT COUNT(*) as count FROM submissions WHERE project_id = ? AND phase = 1",
        [projects[i].id]
      );

      const [phase2Count] = await pool.execute(
        "SELECT COUNT(*) as count FROM submissions WHERE project_id = ? AND phase = 2",
        [projects[i].id]
      );

      projects[i].phase1SubmissionCount = phase1Count[0].count;
      projects[i].phase2SubmissionCount = phase2Count[0].count;
      projects[i].completeSubmissionCount = phase2Count[0].count;

      // Get review count
      const [reviewCount] = await pool.execute(
        "SELECT COUNT(*) as count FROM reviews WHERE project_id = ?",
        [projects[i].id]
      );
      projects[i].reviewCount = reviewCount[0].count;
    }

    res.json({ projects });
  } catch (error) {
    console.error("Error fetching teacher projects:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch projects", error: error.message });
  }
});

// Get student projects (Updated - check manager approval)
app.get("/api/student/projects", authenticateToken, async (req, res) => {
  try {
    // Get projects that are approved and student has access to
    let query = `SELECT p.* FROM projects p WHERE p.status = 'approved'`;
    let queryParams = [];

    if (req.user.role === "student") {
      query += ` AND EXISTS (SELECT 1 FROM student_project_access spa WHERE spa.project_id = p.id AND spa.student_id = ?)`;
      queryParams.push(req.user.id);
    }

    query += ` ORDER BY p.created_at DESC`;

    const [projects] = await pool.execute(query, queryParams);

    // Get files and submission status for each project
    for (let i = 0; i < projects.length; i++) {
      const [files] = await pool.execute(
        "SELECT * FROM project_files WHERE project_id = ?",
        [projects[i].id]
      );
      projects[i].files = files;

      // Check phase 1 submission status
      const [phase1Submissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 1",
        [projects[i].id, req.user.id]
      );
      projects[i].hasSubmittedPhase1 = phase1Submissions.length > 0;
      if (phase1Submissions.length > 0) {
        projects[i].phase1Submission = phase1Submissions[0];
      }

      // Check phase 2 submission status
      const [phase2Submissions] = await pool.execute(
        "SELECT * FROM submissions WHERE project_id = ? AND student_id = ? AND phase = 2",
        [projects[i].id, req.user.id]
      );
      projects[i].hasSubmittedPhase2 = phase2Submissions.length > 0;
      if (phase2Submissions.length > 0) {
        projects[i].phase2Submission = phase2Submissions[0];
      }

      // Get reviews for this student's submissions if both phases are submitted
      if (projects[i].hasSubmittedPhase1 && projects[i].hasSubmittedPhase2) {
        const [reviews] = await pool.execute(
          `SELECT r.*, u.username as reviewer_name 
           FROM reviews r
           JOIN users u ON r.reviewer_id = u.id
           WHERE r.project_id = ? AND r.student_id = ?
           ORDER BY r.created_at DESC`,
          [projects[i].id, req.user.id]
        );
        projects[i].reviews = reviews;
      }

      // Add deadline status
      const currentDate = new Date();
      const firstDeadline = new Date(projects[i].first_deadline);
      const finalDeadline = new Date(projects[i].final_deadline);

      projects[i].phase1DeadlinePassed = currentDate > firstDeadline;
      projects[i].phase2DeadlinePassed = currentDate > finalDeadline;
    }

    res.json({ projects });
  } catch (error) {
    console.error("Error fetching student projects:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch projects", error: error.message });
  }
});

// Get all projects (Updated - removed role restriction)
app.get("/api/all/projects", authenticateToken, async (req, res) => {
  try {
    const [projects] = await pool.execute(
      "SELECT projects.*, users.username as creator_name FROM projects JOIN users ON projects.created_by = users.id ORDER BY created_at DESC"
    );

    // Get files for each project
    for (let i = 0; i < projects.length; i++) {
      const [files] = await pool.execute(
        "SELECT * FROM project_files WHERE project_id = ?",
        [projects[i].id]
      );
      projects[i].files = files;

      // Get submission counts for each phase
      const [phase1Count] = await pool.execute(
        "SELECT COUNT(*) as count FROM submissions WHERE project_id = ? AND phase = 1",
        [projects[i].id]
      );

      const [phase2Count] = await pool.execute(
        "SELECT COUNT(*) as count FROM submissions WHERE project_id = ? AND phase = 2",
        [projects[i].id]
      );

      projects[i].phase1SubmissionCount = phase1Count[0].count;
      projects[i].phase2SubmissionCount = phase2Count[0].count;
      projects[i].completeSubmissionCount = phase2Count[0].count;

      // Get review count
      const [reviewCount] = await pool.execute(
        "SELECT COUNT(*) as count FROM reviews WHERE project_id = ?",
        [projects[i].id]
      );
      projects[i].reviewCount = reviewCount[0].count;

      // Get approved students count
      const [approvedStudentCount] = await pool.execute(
        "SELECT COUNT(*) as count FROM student_project_access WHERE project_id = ?",
        [projects[i].id]
      );
      projects[i].approvedStudentCount = approvedStudentCount[0].count;
    }

    res.json({ projects });
  } catch (error) {
    console.error("Error fetching all projects:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch projects", error: error.message });
  }
});

// Get submissions for a project (teacher view)
app.get(
  "/api/projects/:projectId/submissions",
  authenticateToken,
  async (req, res) => {
    try {
      const { projectId } = req.params;
      const { phase } = req.query; // Optional phase filter (1 or 2)

      // Check if user is authorized to view submissions
      if (
        ![
          "teacher",
          "academic_team",
          "evaluator",
          "manager",
          "coordinator",
        ].includes(req.user.role)
      ) {
        return res.status(403).json({
          message: "You do not have permission to view all submissions",
        });
      }

      // If teacher, verify they created the project
      if (req.user.role === "teacher") {
        const [projects] = await pool.execute(
          "SELECT * FROM projects WHERE id = ? AND created_by = ?",
          [projectId, req.user.id]
        );

        if (projects.length === 0) {
          return res.status(403).json({
            message: "You do not have permission to view these submissions",
          });
        }
      }

      // Build query based on phase filter
      let query = `SELECT s.*, u.username, u.email FROM submissions s
                  INNER JOIN users u ON s.student_id = u.id
                  WHERE s.project_id = ?`;

      const queryParams = [projectId];

      if (phase) {
        query += " AND s.phase = ?";
        queryParams.push(phase);
      }

      query += " ORDER BY s.submitted_at DESC";

      // Get submissions
      const [submissions] = await pool.execute(query, queryParams);

      // For each submission, check if it has reviews
      for (let i = 0; i < submissions.length; i++) {
        const [reviews] = await pool.execute(
          `SELECT r.*, u.username as reviewer_name 
           FROM reviews r
           JOIN users u ON r.reviewer_id = u.id
           WHERE r.submission_id = ?`,
          [submissions[i].id]
        );
        submissions[i].reviews = reviews;
      }

      res.json({ submissions });
    } catch (error) {
      console.error("Error fetching submissions:", error);
      res
        .status(500)
        .json({ message: "Failed to fetch submissions", error: error.message });
    }
  }
);

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Get all pending users for approval
app.get("/api/admin/pending-users", authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view pending users" });
    }

    // Get all users who are not approved
    const [users] = await pool.execute(
      `SELECT id, username, email, role, created_at 
       FROM users 
       WHERE is_approved = 0 AND role != 'admin'
       ORDER BY created_at DESC`
    );

    res.json({ users });
  } catch (error) {
    console.error("Error fetching pending users:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch pending users", error: error.message });
  }
});

// Approve or reject a user
app.post(
  "/api/admin/users/:userId/approve",
  authenticateToken,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { approve } = req.body; // true to approve, false to reject

      // Check if user is admin
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can approve/reject users" });
      }

      // Check if user exists
      const [users] = await pool.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        [userId]
      );

      if (users.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = users[0];

      // Don't allow modifying admin accounts
      if (user.role === "admin") {
        return res
          .status(403)
          .json({ message: "Cannot modify admin accounts" });
      }

      // Update user approval status
      await pool.execute("UPDATE users SET is_approved = ? WHERE id = ?", [
        approve ? 1 : 0,
        userId,
      ]);

      res.json({
        message: approve
          ? "User approved successfully"
          : "User rejected successfully",
        userId: parseInt(userId),
        username: user.username,
        role: user.role,
        approved: approve,
      });
    } catch (error) {
      console.error("Error updating user approval:", error);
      res.status(500).json({
        message: "Failed to update user approval",
        error: error.message,
      });
    }
  }
);

// Get approval status for current user
app.get("/api/users/approval-status", authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(
      "SELECT is_approved FROM users WHERE id = ?",
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      is_approved: users[0].is_approved === 1,
      role: req.user.role,
    });
  } catch (error) {
    console.error("Error fetching approval status:", error);
    res.status(500).json({
      message: "Failed to fetch approval status",
      error: error.message,
    });
  }
});

// Get all users (admin only)
app.get("/api/admin/users", authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view all users" });
    }

    // Get all users except admins
    const [users] = await pool.execute(
      `SELECT id, username, email, role, created_at, is_approved 
       FROM users 
       WHERE role != 'admin'
       ORDER BY created_at DESC`
    );

    res.json({ users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch users", error: error.message });
  }
});

// Get all pending users for approval (admin only)
app.get("/api/admin/pending-users", authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view pending users" });
    }

    // Get all users who are not approved
    const [users] = await pool.execute(
      `SELECT id, username, email, role, created_at 
       FROM users 
       WHERE is_approved = 0 AND role != 'admin'
       ORDER BY created_at DESC`
    );

    res.json({ users });
  } catch (error) {
    console.error("Error fetching pending users:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch pending users", error: error.message });
  }
});

// Approve or reject a user (admin only)
app.post(
  "/api/admin/users/:userId/approve",
  authenticateToken,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { approve } = req.body; // true to approve, false to revoke access

      // Check if user is admin
      if (req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Only admins can approve/reject users" });
      }

      // Check if user exists
      const [users] = await pool.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        [userId]
      );

      if (users.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = users[0];

      // Don't allow modifying admin accounts
      if (user.role === "admin") {
        return res
          .status(403)
          .json({ message: "Cannot modify admin accounts" });
      }

      // Update user approval status
      await pool.execute("UPDATE users SET is_approved = ? WHERE id = ?", [
        approve ? 1 : 0,
        userId,
      ]);

      res.json({
        message: approve
          ? "User approved successfully"
          : "User access revoked successfully",
        userId: parseInt(userId),
        username: user.username,
        role: user.role,
        is_approved: approve,
      });
    } catch (error) {
      console.error("Error updating user approval:", error);
      res.status(500).json({
        message: "Failed to update user approval",
        error: error.message,
      });
    }
  }
);

// Get approval status for current user
app.get("/api/users/approval-status", authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(
      "SELECT is_approved FROM users WHERE id = ?",
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      is_approved: users[0].is_approved === 1,
      role: req.user.role,
    });
  } catch (error) {
    console.error("Error fetching approval status:", error);
    res.status(500).json({
      message: "Failed to fetch approval status",
      error: error.message,
    });
  }
});

// Get admin dashboard stats
app.get("/api/admin/dashboard-stats", authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Only admins can view dashboard stats" });
    }

    // Get total users count (excluding admins)
    const [totalUsers] = await pool.execute(
      "SELECT COUNT(*) as count FROM users WHERE role != 'admin'"
    );

    // Get approved users count
    const [approvedUsers] = await pool.execute(
      "SELECT COUNT(*) as count FROM users WHERE is_approved = 1 AND role != 'admin'"
    );

    // Get pending users count
    const [pendingUsers] = await pool.execute(
      "SELECT COUNT(*) as count FROM users WHERE is_approved = 0 AND role != 'admin'"
    );

    // Get count by role
    const [roleStats] = await pool.execute(`
      SELECT role, COUNT(*) as count 
      FROM users 
      WHERE role != 'admin'
      GROUP BY role
    `);

    res.json({
      totalUsers: totalUsers[0].count,
      approvedUsers: approvedUsers[0].count,
      pendingUsers: pendingUsers[0].count,
      roleStats: roleStats.reduce((acc, curr) => {
        acc[curr.role] = curr.count;
        return acc;
      }, {}),
    });
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    res.status(500).json({
      message: "Failed to fetch dashboard stats",
      error: error.message,
    });
  }
});

// Delete a project and all associated data
app.delete("/api/projects/:projectId", authenticateToken, async (req, res) => {
  try {
    const { projectId } = req.params;

    // Check if user has permission to delete projects
    if (
      !["admin", "teacher", "coordinator", "manager"].includes(req.user.role)
    ) {
      return res
        .status(403)
        .json({ message: "You do not have permission to delete projects" });
    }

    // If user is a teacher, verify they created the project
    if (req.user.role === "teacher") {
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ? AND created_by = ?",
        [projectId, req.user.id]
      );

      if (projects.length === 0) {
        return res
          .status(403)
          .json({ message: "You can only delete projects you created" });
      }
    }

    // Check if project exists before attempting deletion
    const [projectExists] = await pool.execute(
      "SELECT id FROM projects WHERE id = ?",
      [projectId]
    );

    if (projectExists.length === 0) {
      return res.status(404).json({ message: "Project not found" });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Delete all reviews for submissions of this project
      await connection.execute(
        "DELETE r FROM reviews r INNER JOIN submissions s ON r.submission_id = s.id WHERE s.project_id = ?",
        [projectId]
      );

      // Delete all submissions
      await connection.execute("DELETE FROM submissions WHERE project_id = ?", [
        projectId,
      ]);

      // Delete all student project access records
      await connection.execute(
        "DELETE FROM student_project_access WHERE project_id = ?",
        [projectId]
      );

      // Get file URLs before deleting from database
      const [files] = await connection.execute(
        "SELECT file_url FROM project_files WHERE project_id = ?",
        [projectId]
      );

      // Delete all project files from database
      await connection.execute(
        "DELETE FROM project_files WHERE project_id = ?",
        [projectId]
      );

      // Delete the project itself
      await connection.execute("DELETE FROM projects WHERE id = ?", [
        projectId,
      ]);

      await connection.commit();

      // Delete files from Cloudinary
      for (const file of files) {
        try {
          const publicId = file.file_url.split("/").pop()?.split(".")[0];
          if (publicId) {
            await cloudinary.uploader.destroy(publicId);
          }
        } catch (cloudinaryError) {
          console.error(
            "Error deleting file from Cloudinary:",
            cloudinaryError
          );
        }
      }

      res.json({
        message: "Project and all associated data deleted successfully",
        projectId: parseInt(projectId),
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Error deleting project:", error);
    res.status(500).json({
      message: "Failed to delete project",
      error: error.message,
    });
  }
});

// Add this after other project routes
app.put(
  "/api/projects/:projectId/deadlines",
  authenticateToken,
  async (req, res) => {
    try {
      const { projectId } = req.params;
      const { firstDeadline, finalDeadline } = req.body;

      // Debug logging
      console.log("=== Deadline Update Request ===");
      console.log("Project ID:", projectId);
      console.log("Request Body:", JSON.stringify(req.body, null, 2));
      console.log("User:", JSON.stringify(req.user, null, 2));

      // Input validation
      if (!projectId) {
        console.error("Missing project ID");
        return res.status(400).json({ message: "Project ID is required" });
      }

      if (!firstDeadline || !finalDeadline) {
        console.error("Missing deadline values:", {
          firstDeadline,
          finalDeadline,
        });
        return res.status(400).json({ message: "Both deadlines are required" });
      }

      // Check user permissions
      if (
        !["teacher", "academic_team", "coordinator", "admin"].includes(
          req.user.role
        )
      ) {
        console.error("Permission denied for user role:", req.user.role);
        return res
          .status(403)
          .json({ message: "You don't have permission to update deadlines" });
      }

      // Check if project exists
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ?",
        [projectId]
      );

      console.log("Project query result:", JSON.stringify(projects, null, 2));

      if (!projects || projects.length === 0) {
        console.error("Project not found:", projectId);
        return res.status(404).json({ message: "Project not found" });
      }

      // Parse and validate dates
      let parsedFirstDeadline, parsedFinalDeadline;
      try {
        parsedFirstDeadline = new Date(firstDeadline);
        parsedFinalDeadline = new Date(finalDeadline);

        if (
          isNaN(parsedFirstDeadline.getTime()) ||
          isNaN(parsedFinalDeadline.getTime())
        ) {
          throw new Error("Invalid date format");
        }
      } catch (error) {
        console.error("Date parsing error:", error);
        return res.status(400).json({ message: "Invalid date format" });
      }

      if (parsedFirstDeadline >= parsedFinalDeadline) {
        console.error("Invalid deadline order:", {
          parsedFirstDeadline,
          parsedFinalDeadline,
        });
        return res
          .status(400)
          .json({ message: "First deadline must be before final deadline" });
      }

      // Format dates for MySQL
      const mysqlFirstDeadline = parsedFirstDeadline
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");
      const mysqlFinalDeadline = parsedFinalDeadline
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      console.log("Formatted dates for MySQL:", {
        mysqlFirstDeadline,
        mysqlFinalDeadline,
      });

      // Update deadlines
      try {
        const [result] = await pool.execute(
          "UPDATE projects SET first_deadline = ?, final_deadline = ? WHERE id = ?",
          [mysqlFirstDeadline, mysqlFinalDeadline, projectId]
        );

        console.log("Update query result:", JSON.stringify(result, null, 2));

        if (result.affectedRows === 0) {
          console.error("No rows affected in update");
          return res
            .status(500)
            .json({ message: "Failed to update deadlines" });
        }

        console.log("Deadlines updated successfully");
        return res.json({
          message: "Deadlines updated successfully",
          data: {
            firstDeadline: mysqlFirstDeadline,
            finalDeadline: mysqlFinalDeadline,
          },
        });
      } catch (dbError) {
        console.error("Database error:", dbError);
        return res.status(500).json({
          message: "Database error while updating deadlines",
          error: dbError.message,
        });
      }
    } catch (error) {
      console.error("Unexpected error in deadline update:", error);
      return res.status(500).json({
        message: "Failed to update deadlines",
        error: error.message,
      });
    }
  }
);

// Add project state update endpoint
app.put(
  "/api/projects/:projectId/state",
  authenticateToken,
  async (req, res) => {
    try {
      const { projectId } = req.params;
      const { state, firstDeadline, finalDeadline } = req.body;

      console.log("=== Project State Update Request ===");
      console.log("Project ID:", projectId);
      console.log("Request Body:", JSON.stringify(req.body, null, 2));
      console.log("User:", JSON.stringify(req.user, null, 2));

      // Check user permissions
      if (
        !["teacher", "academic_team", "coordinator", "admin"].includes(
          req.user.role
        )
      ) {
        console.error("Permission denied for user role:", req.user.role);
        return res.status(403).json({
          message: "You don't have permission to update project state",
        });
      }

      // Check if project exists
      const [projects] = await pool.execute(
        "SELECT * FROM projects WHERE id = ?",
        [projectId]
      );

      if (!projects || projects.length === 0) {
        console.error("Project not found:", projectId);
        return res.status(404).json({ message: "Project not found" });
      }

      const project = projects[0];

      // Handle state change to 'past'
      if (state === "past") {
        // Simply update the state to past
        const [result] = await pool.execute(
          "UPDATE projects SET state = 'past' WHERE id = ?",
          [projectId]
        );

        if (result.affectedRows === 0) {
          return res
            .status(500)
            .json({ message: "Failed to update project state" });
        }

        return res.json({ message: "Project marked as past" });
      }

      // Handle state change to 'active'
      if (state === "active") {
        // If current state is past, new deadlines are required
        if (
          project.state === "past" ||
          (project.first_deadline &&
            new Date(project.first_deadline) < new Date()) ||
          (project.final_deadline &&
            new Date(project.final_deadline) < new Date())
        ) {
          if (!firstDeadline || !finalDeadline) {
            return res.status(400).json({
              message:
                "New deadlines are required when activating a past project or updating passed deadlines",
              requiresDeadlines: true,
            });
          }

          // Validate new deadlines
          const firstDate = new Date(firstDeadline);
          const finalDate = new Date(finalDeadline);

          if (isNaN(firstDate.getTime()) || isNaN(finalDate.getTime())) {
            return res.status(400).json({ message: "Invalid date format" });
          }

          if (firstDate >= finalDate) {
            return res.status(400).json({
              message: "First deadline must be before final deadline",
            });
          }

          // Format dates for MySQL
          const mysqlFirstDeadline = firstDate
            .toISOString()
            .slice(0, 19)
            .replace("T", " ");
          const mysqlFinalDeadline = finalDate
            .toISOString()
            .slice(0, 19)
            .replace("T", " ");

          // Update state and deadlines
          const [result] = await pool.execute(
            "UPDATE projects SET state = 'active', first_deadline = ?, final_deadline = ? WHERE id = ?",
            [mysqlFirstDeadline, mysqlFinalDeadline, projectId]
          );

          if (result.affectedRows === 0) {
            return res.status(500).json({
              message: "Failed to update project state and deadlines",
            });
          }

          return res.json({
            message: "Project activated with new deadlines",
            data: {
              firstDeadline: mysqlFirstDeadline,
              finalDeadline: mysqlFinalDeadline,
            },
          });
        } else {
          // Just update state to active if deadlines haven't passed
          const [result] = await pool.execute(
            "UPDATE projects SET state = 'active' WHERE id = ?",
            [projectId]
          );

          if (result.affectedRows === 0) {
            return res
              .status(500)
              .json({ message: "Failed to update project state" });
          }

          return res.json({ message: "Project marked as active" });
        }
      }

      return res.status(400).json({ message: "Invalid state value" });
    } catch (error) {
      console.error("Error updating project state:", error);
      res.status(500).json({
        message: "Failed to update project state",
        error: error.message,
      });
    }
  }
);
