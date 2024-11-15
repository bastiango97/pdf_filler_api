const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    // Get the token from the cookies
    const token = req.cookies.token;

    // Check if the token is present
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        // Verify the token using the secret key
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach the decoded user info to the request
        next(); // Move to the next middleware or route handler
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token.' });
    }
};

module.exports = authenticateToken;
