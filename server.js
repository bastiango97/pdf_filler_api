require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const authenticateToken = require('./middleware/authenticateToken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cookieParser()); // Add this line to enable cookie parsing
app.use(cors({
    origin: ['http://localhost:3001', 'https://plataforma-formatos.onrender.com'], // Replace with the port where your React app is running
    credentials: true
}));

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

const jwtSecret = process.env.JWT_SECRET;
const saltRounds = 10;

// Register a new user
app.post('/register', async (req, res) => {
    const { email, password, firstName, lastName } = req.body;

    try {
        // Hash the password
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert the new user into the database
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, passwordHash, firstName, lastName]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.rows[0].user_id });
    } catch (error) {
        if (error.code === '23505') { // Unique constraint violation (duplicate email)
            res.status(400).json({ error: 'Email already in use' });
        } else {
            console.error(error);
            res.status(500).json({ error: 'Server error' });
        }
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
        sameSite: 'Strict',
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

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
