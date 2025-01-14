require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const authenticateToken = require('./middleware/authenticateToken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const app = express();
const axios = require('axios');
app.use(express.json());
app.use(cookieParser()); // Add this line to enable cookie parsing
app.use(cors({
    origin: ['http://localhost:3001', 'https://plataforma-formatos.onrender.com'], // Replace with the port where your React app is running
    credentials: true
}));
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const transporter = nodemailer.createTransport({
    host: 'mail.migestor.io',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: {
        rejectUnauthorized: false, // Allows connections with self-signed certificates
    },
});


//Authentication for ADMIN 
const FORMIO_ADMIN_EMAIL = process.env.FORMIO_ADMIN_EMAIL;
const FORMIO_ADMIN_PASSWORD = process.env.FORMIO_ADMIN_PASSWORD;
const FORMIO_PROJECT_URL = process.env.FORMIO_PROJECT_URL;
const jwtSecret = process.env.JWT_SECRET;
const saltRounds = 10;

const BASE_URL = process.env.BASE_URL;

//FUNCIONES PARA DESCARGAR EL PDF DE LA API DE FORMIO 
async function authenticateAdmin() {
    const response = await axios.post(`${FORMIO_PROJECT_URL}/admin/login`, {
        data: {
            email: FORMIO_ADMIN_EMAIL,
            password: FORMIO_ADMIN_PASSWORD,
        },
    });
    return response.headers['x-jwt-token'];
}

async function createDownloadToken(jwtToken, formId, submissionId) {
    const response = await axios.get(`${FORMIO_PROJECT_URL}/token`, {
        headers: {
            'x-allow': `GET:/form/${formId}/submission/${submissionId}/download`,
            'x-expire': '86400',
            'x-jwt-token': jwtToken,
        },
    });
    return response.data.key;
}

app.post('/generate-download-link', async (req, res) => {
    const { formId, submissionId } = req.body;

    try {
        // Step 1: Authenticate as Admin
        const jwtToken = await authenticateAdmin();

        // Step 2: Create the Download Token
        const downloadKey = await createDownloadToken(jwtToken, formId, submissionId);

        // Step 3: Generate the Download Link
        const downloadLink = `${FORMIO_PROJECT_URL}/form/${formId}/submission/${submissionId}/download?token=${downloadKey}`;

        // Step 4: Send the Link to the Frontend
        res.json({ downloadLink });
    } catch (error) {
        console.error('Error generating download link:', error.message);
        res.status(500).json({ error: 'Failed to generate download link' });
    }
});




app.post('/register', async (req, res) => {
    const { email, password, firstName, lastName } = req.body;

    try {
        // Check if the user already exists
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email already in use' });
        }

        // Hash the password
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Generate a verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        // Set token expiration to 1 month (30 days)
        const verificationTokenExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days in milliseconds


        // Insert the new user into the database
        const result = await pool.query(
            `INSERT INTO users (email, password_hash, first_name, last_name, verification_token, verification_token_expires)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [email, passwordHash, firstName, lastName, verificationToken, verificationTokenExpires]
        );

        // Send a verification email
        const verificationLink = `${BASE_URL}/verify-account?token=${verificationToken}`;
        await transporter.sendMail({
            from: '"MiGestor" <no-reply@migestor.io>', // Sender's name and email
            to: email, // Recipient's email
            subject: 'Verifica tu cuenta - MiGestor',
            html: `
                <div style="
                    font-family: Arial, sans-serif;
                    max-width: 600px;
                    margin: 0 auto;
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                ">
                    <div style="
                        background-color: #004085;
                        color: #ffffff;
                        text-align: center;
                        padding: 20px;
                    ">
                        <h1 style="margin: 0; font-size: 24px;">¡Verifica tu cuenta!</h1>
                    </div>
                    <div style="
                        padding: 30px;
                        color: #444444;
                        line-height: 1.6;
                    ">
                        <p>Hola <strong>${firstName}</strong>,</p>
                        <p>
                            Gracias por registrarte en <strong>MiGestor</strong>. Para completar tu registro y activar tu cuenta,
                            haz clic en el botón de abajo.
                        </p>
                        <div style="
                            text-align: center;
                            margin: 30px 0;
                        ">
                            <a href="${verificationLink}" style="
                                background-color: #28a745;
                                color: #ffffff;
                                text-decoration: none;
                                padding: 12px 24px;
                                font-size: 16px;
                                border-radius: 5px;
                                display: inline-block;
                            ">
                                Verificar Cuenta
                            </a>
                        </div>
                        <p>
                            Si tienes algún problema, no dudes en ponerte en contacto con nuestro equipo de soporte.
                        </p>
                    </div>
                    <div style="
                        background-color: #f8f9fa;
                        color: #888888;
                        text-align: center;
                        padding: 15px;
                        font-size: 12px;
                    ">
                        <p style="margin: 0;">&copy; ${new Date().getFullYear()} MiGestor. Todos los derechos reservados.</p>
                        <p style="margin: 0;">
                            <a href="https://migestor.io/privacidad" style="color: #888888; text-decoration: none;">Política de Privacidad</a>
                            |
                            <a href="https://migestor.io/soporte" style="color: #888888; text-decoration: none;">Soporte</a>
                        </p>
                    </div>
                </div>
            `
        });
        

        res.status(201).json({ message: 'User registered successfully. Please verify your email.' });
    } catch (error) {
        if (error.code === '23505') { // Unique constraint violation (duplicate email)
            res.status(400).json({ error: 'Email already in use' });
        } else {
            console.error(error);
            res.status(500).json({ error: 'Server error' });
        }
    }
});

app.post('/verify-account', async (req, res) => {
    const { token } = req.body; // Extract the token from the request body

    if (!token) {
        return res.status(400).json({ error: 'Verification token is required' });
    }

    try {
        // Find the user with the given verification token
        const result = await pool.query(
            `SELECT * FROM users WHERE verification_token = $1`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired verification token' });
        }

        const user = result.rows[0];

        // Update the user's record to mark the account as verified
        await pool.query(
            `UPDATE users SET is_verified = TRUE, verification_token = NULL, verification_token_expires = NULL WHERE user_id = $1`,
            [user.user_id]
        );

        res.status(200).json({ message: 'Account verified successfully. You can now log in.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});



// Login a user
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Retrieve the user from the database
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = result.rows[0];

        // Compare the hashed password
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate a JWT
        const token = jwt.sign({ userId: user.user_id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Set the token as an HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,      // Prevents JavaScript access
            secure: process.env.NODE_ENV === 'production', // Use true if using HTTPS in production
            sameSite: 'None',  // Prevents cross-site request forgery
            maxAge: 2 * 24 * 60 * 60 * 1000      // Token expiration in milliseconds (1 hour)
        });

        // Send a response without including the token in the JSON body
        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});


app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        // Check if the user exists
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'No account found with that email' });
        }

        const user = result.rows[0];

        // Generate a reset token and expiration
        const resetToken = crypto.randomBytes(32).toString('hex');
        // Set reset token expiration to 1 hour
        const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour in milliseconds


        // Update the user record with the reset token and expiration
        await pool.query(
            `UPDATE users SET reset_password_token = $1, reset_password_token_expires = $2 WHERE user_id = $3`,
            [resetToken, resetTokenExpires, user.user_id]
        );

        // Send the password reset email
        const resetLink = `${BASE_URL}/reset-password?token=${resetToken}`;
        await transporter.sendMail({
            from: '"MiGestor" <no-reply@migestor.io>', // Sender's name and email
            to: email, // Recipient's email
            subject: 'Restablece tu contraseña - MiGestor',
            html: `
                <div style="
                    font-family: Arial, sans-serif;
                    max-width: 600px;
                    margin: 0 auto;
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                ">
                    <div style="
                        background-color: #dc3545;
                        color: #ffffff;
                        text-align: center;
                        padding: 20px;
                    ">
                        <h1 style="margin: 0; font-size: 24px;">¡Restablece tu contraseña!</h1>
                    </div>
                    <div style="
                        padding: 30px;
                        color: #444444;
                        line-height: 1.6;
                    ">
                        <p>Hola <strong>${user.first_name}</strong>,</p>
                        <p>
                            Hemos recibido una solicitud para restablecer tu contraseña en <strong>MiGestor</strong>. 
                            Si realizaste esta solicitud, haz clic en el botón de abajo para establecer una nueva contraseña.
                        </p>
                        <div style="
                            text-align: center;
                            margin: 30px 0;
                        ">
                            <a href="${resetLink}" style="
                                background-color: #28a745;
                                color: #ffffff;
                                text-decoration: none;
                                padding: 12px 24px;
                                font-size: 16px;
                                border-radius: 5px;
                                display: inline-block;
                            ">
                                Restablecer Contraseña
                            </a>
                        </div>
                        <p>
                            Si no realizaste esta solicitud, puedes ignorar este mensaje. Tu cuenta seguirá siendo segura.
                        </p>
                    </div>
                    <div style="
                        background-color: #f8f9fa;
                        color: #888888;
                        text-align: center;
                        padding: 15px;
                        font-size: 12px;
                    ">
                        <p style="margin: 0;">&copy; ${new Date().getFullYear()} MiGestor. Todos los derechos reservados.</p>
                        <p style="margin: 0;">
                            <a href="https://migestor.io/privacidad" style="color: #888888; text-decoration: none;">Política de Privacidad</a>
                            |
                            <a href="https://migestor.io/soporte" style="color: #888888; text-decoration: none;">Soporte</a>
                        </p>
                    </div>
                </div>
            `
        });
        

        res.status(200).json({ message: 'Password reset email sent. Please check your inbox.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});


app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required' });
    }

    try {
        // Find the user with the provided reset token and ensure the token has not expired
        const result = await pool.query(
            `SELECT * FROM users WHERE reset_password_token = $1`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }

        const user = result.rows[0];

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password and invalidate the reset token
        await pool.query(
            `UPDATE users SET password_hash = $1, reset_password_token = NULL, reset_password_token_expires = NULL WHERE user_id = $2`,
            [hashedPassword, user.user_id]
        );

        res.status(200).json({ message: 'Password reset successfully. You can now log in with your new password.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});



app.get('/formats', authenticateToken, async (req, res) => {
    try {
        // Updated query to include format ID
        const result = await pool.query(`
            SELECT 
                f.id AS format_id,
                a.name AS insurance_company, 
                f.name AS format_name, 
                f.form_io_link AS form_link
            FROM 
                formato f
            JOIN 
                aseguradoras a ON f.aseguradora_id = a.id
        `);

        // Transform the query result into the desired JSON format
        const formats = result.rows.map(row => ({
            format_id: row.format_id,              // Include format ID
            insurance_company: row.insurance_company,
            format_name: row.format_name,
            form_link: row.form_link
        }));

        // Send the response as JSON
        res.status(200).json(formats);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while fetching formats' });
    }
});

app.get('/formats/:id/pdf', authenticateToken, async (req, res) => {
    const formatId = req.params.id;

    try {
        // Query to retrieve the PDF data and filename based on the format_id
        const result = await pool.query(
            `SELECT pdf_data, filename FROM formatoPDF WHERE formato_id = $1`,
            [formatId]
        );

        // Check if a PDF was found
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'PDF not found for this format ID' });
        }

        const pdfData = result.rows[0].pdf_data;
        const filename = result.rows[0].filename;

        // Set the response headers to indicate a file download
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/pdf');

        // Send the PDF data as the response
        res.send(pdfData);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error while fetching PDF' });
    }
});

// Check token validity
app.get('/auth-check', authenticateToken, (req, res) => {
    try {
        // If the authenticateToken middleware passes, the token is valid
        res.status(200).json({ message: 'Token is valid', user: req.user });
    } catch (error) {
        console.error('Error in /auth-check:', error);
        res.status(500).json({ error: 'Server error during authentication check' });
    }
});
//Logout 
app.post('/logout', (req, res) => {
    res.cookie('token', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'None',
        expires: new Date(0), // Set the expiration date to a past time
    });
    res.status(200).json({ message: 'Logged out successfully' });
});

// Get all unique insurance companies
app.get('/insurance-companies', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT name AS insurance_company
            FROM aseguradoras
        `);

        const insuranceCompanies = result.rows.map(row => row.insurance_company);

        res.status(200).json(insuranceCompanies);
    } catch (error) {
        console.error('Error fetching insurance companies:', error);
        res.status(500).json({ error: 'Server error while fetching insurance companies' });
    }
});

// Get all formats for a specific insurance company
app.get('/formats/:companyId', authenticateToken, async (req, res) => {
    const { companyId } = req.params;

    try {
        const result = await pool.query(`
            SELECT 
                f.id AS format_id,
                f.name AS format_name,
                f.form_io_link AS form_link
            FROM 
                formato f
            JOIN 
                aseguradoras a ON f.aseguradora_id = a.id
            WHERE 
                a.name ILIKE $1
        `, [companyId.replace("-", " ")]); // Replace hyphens with spaces for company names like "la-latino"

        const formats = result.rows.map(row => ({
            format_id: row.format_id,
            format_name: row.format_name,
            form_link: row.form_link
        }));

        res.status(200).json(formats);
    } catch (error) {
        console.error('Error fetching formats for company:', error);
        res.status(500).json({ error: 'Server error while fetching formats' });
    }
});
// Get specific format details for a given insurance company and format name
app.get('/formats/:companyId/:formatId', authenticateToken, async (req, res) => {
    const { companyId, formatId } = req.params;

    try {
        // Query to get the format and associated PDF for the specified company and format name
        const result = await pool.query(`
            SELECT 
                f.id AS format_id,
                f.name AS format_name,
                f.form_io_link AS api_link,
                pdf.filename AS pdf_filename,
                pdf.pdf_data AS pdf_data
            FROM 
                formato f
            JOIN 
                aseguradoras a ON f.aseguradora_id = a.id
            LEFT JOIN 
                formatoPDF pdf ON pdf.formato_id = f.id
            WHERE 
                a.name ILIKE $1
                AND f.name ILIKE $2
        `, [companyId.replace("-", " "), formatId.replace("-", " ")]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Format not found for the specified company and format ID' });
        }

        // Extract format details
        const format = {
            format_id: result.rows[0].format_id,
            format_name: result.rows[0].format_name,
            api_link: result.rows[0].api_link,
            pdf_filename: result.rows[0].pdf_filename,
            pdf_data: result.rows[0].pdf_data,
        };

        res.status(200).json(format);
    } catch (error) {
        console.error('Error fetching format details:', error);
        res.status(500).json({ error: 'Server error while fetching format details' });
    }
});


// REGISTRO DE LLENADO DE FORMATOS
app.post('/create-registration', authenticateToken, async (req, res) => {
    const {
        format_id,
        assignee_id, // Optional
        form_id,
        submission_id,
        status, // Optional
        notes, // Optional
    } = req.body;

    try {
        // Extract agent_id from the JWT token (via the middleware)
        const agent_id = req.user.userId;

        // Insert into the registrations table
        const result = await pool.query(
            `INSERT INTO registrations (agent_id, format_id, assignee_id, form_id, submission_id, created_at, status, notes)
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7)
             RETURNING *`,
            [agent_id, format_id, assignee_id || null, form_id, submission_id, status || 'created', notes || null]
        );

        res.status(201).json({ message: 'Registration created successfully', registration: result.rows[0] });
    } catch (error) {
        console.error('Error creating registration:', error.message);
        res.status(500).json({ error: 'Failed to create registration' });
    }
});

app.get('/registrations', authenticateToken, async (req, res) => {
    const agentId = req.user.userId; // Extract agent ID from JWT

    try {
        const query = `
            SELECT 
                r.registration_id, 
                f.name AS format_name,
                r.created_at,
                r.status,
                r.notes
            FROM 
                registrations r
            JOIN 
                formato f ON r.format_id = f.id
            WHERE 
                r.agent_id = $1
            ORDER BY 
                r.created_at DESC;
        `;
        const result = await pool.query(query, [agentId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'No registrations found for this agent' });
        }

        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching registrations:', error);
        res.status(500).json({ error: 'Failed to fetch registrations' });
    }
});


// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
