const express = require('express');
const router = express.Router();
const db = require('../models/db');
const bcrypt = require('bcrypt');

// Authentication middleware
const authenticateUser = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ 
            success: false,
            error: 'Authentication required' 
        });
    }
    req.userId = req.session.userId;
    next();
};

// Authentication routes
router.post('/auth/login', async (req, res) => {
    console.log('Received login request:', { email: req.body.email });
    try {
        const { email, password } = req.body;
        
        // Input validation
        if (!email || !password) {
            console.log('Missing required fields:', { email: !!email, password: !!password });
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password are required' 
            });
        }

        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            console.log('Invalid email format:', email);
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid email format' 
            });
        }

        // Attempt login
        console.log('Attempting login...');
        const user = await db.loginUser(email, password);
        
        // Set session
        req.session.userId = user.id;
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Failed to create session'
                });
            }
            
            console.log('Login successful:', { userId: user.id });
            res.json({ 
                success: true, 
                userId: user.id,
                username: user.username,
                email: user.email
            });
        });
    } catch (error) {
        console.error('Login error:', error.message);
        if (error.message === 'User not found' || error.message === 'Invalid password') {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }
        res.status(500).json({ 
            success: false, 
            error: 'An error occurred during login' 
        });
    }
});

// Register new user
router.post('/auth/register', async (req, res) => {
    console.log('Received registration request:', { email: req.body.email });
    try {
        const { fullName, email, password, confirmPassword } = req.body;

        // Validate input
        if (!fullName || !email || !password || !confirmPassword) {
            return res.status(400).json({ 
                success: false,
                error: 'All fields are required' 
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid email format' 
            });
        }

        // Validate password match
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'Passwords do not match'
            });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user
        const userId = await db.createUser(fullName, email, hashedPassword);
        
        // Set session
        req.session.userId = userId;
        
        // Save session
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Failed to create session'
                });
            }
            
            console.log('Registration successful:', { userId });
            res.json({ 
                success: true, 
                message: 'Registration successful',
                userId: userId,
                username: fullName,
                email: email
            });
        });

    } catch (error) {
        console.error('Registration error:', error);
        if (error.message.includes('UNIQUE constraint failed')) {
            res.status(400).json({ 
                success: false,
                error: 'Email already registered' 
            });
        } else {
            res.status(500).json({ 
                success: false,
                error: 'Registration failed' 
            });
        }
    }
});

// Login user
router.post('/auth/logout', authenticateUser, (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            res.status(500).json({ 
                success: false,
                error: 'Logout failed' 
            });
        } else {
            res.json({ 
                success: true, 
                message: 'Logout successful' 
            });
        }
    });
});

// Get user profile
router.get('/profile', authenticateUser, async (req, res) => {
    try {
        const user = await db.getUserById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Remove sensitive information
        delete user.password;
        
        res.json(user);
    } catch (error) {
        console.error('Error getting user profile:', error);
        res.status(500).json({ error: 'Failed to get user profile' });
    }
});

// User routes
router.get('/users/:id', async (req, res) => {
    try {
        const user = await db.getUser(req.params.id);
        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Goals routes
router.post('/goals', authenticateUser, async (req, res) => {
    try {
        const { title, description, targetValue, unit, deadline } = req.body;
        const goalId = await db.createGoal(req.userId, title, description, targetValue, unit, deadline);
        res.json({ 
            success: true, 
            goalId,
            message: 'Goal created successfully'
        });
    } catch (error) {
        console.error('Error creating goal:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create goal' 
        });
    }
});

router.get('/goals', authenticateUser, async (req, res) => {
    try {
        const goals = await db.getGoals(req.userId);
        res.json({
            success: true,
            goals: goals
        });
    } catch (error) {
        console.error('Error fetching goals:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch goals' 
        });
    }
});

// Tracking data routes
router.post('/tracking', async (req, res) => {
    try {
        const { userId, goalId, value, date, notes } = req.body;
        const trackingId = await db.addTrackingData(userId, goalId, value, date, notes);
        res.json({ success: true, trackingId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/tracking/:userId/:goalId', async (req, res) => {
    try {
        const trackingData = await db.getTrackingData(req.params.userId, req.params.goalId);
        res.json(trackingData);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Analytics routes
router.post('/analytics', async (req, res) => {
    try {
        const { userId, goalId, metricName, metricValue, date } = req.body;
        const analyticsId = await db.addAnalytics(userId, goalId, metricName, metricValue, date);
        res.json({ success: true, analyticsId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/analytics/:userId/:goalId', async (req, res) => {
    try {
        const analytics = await db.getAnalytics(req.params.userId, req.params.goalId);
        res.json(analytics);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// User settings routes
router.put('/settings/:userId', async (req, res) => {
    try {
        const { theme, notificationsEnabled, measurementUnit } = req.body;
        const settingsId = await db.updateUserSettings(
            req.params.userId,
            theme,
            notificationsEnabled,
            measurementUnit
        );
        res.json({ success: true, settingsId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/settings/:userId', async (req, res) => {
    try {
        const settings = await db.getUserSettings(req.params.userId);
        if (settings) {
            res.json(settings);
        } else {
            res.status(404).json({ success: false, message: 'Settings not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Hydration goals routes
router.get('/hydration/daily-goal', authenticateUser, async (req, res) => {
    try {
        const goal = await db.getDailyGoal(req.userId);
        res.json(goal || { target_value: 2000 }); // Default to 2000ml if no goal set
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/hydration/daily-goal', authenticateUser, async (req, res) => {
    try {
        const { target } = req.body;
        await db.updateDailyGoal(req.userId, target);
        res.json({ message: 'Daily goal updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/hydration/weekly-goals', authenticateUser, async (req, res) => {
    try {
        const goals = await db.getWeeklyGoals(req.userId);
        res.json(goals);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/hydration/weekly-goals', authenticateUser, async (req, res) => {
    try {
        const { title, description, target, unit } = req.body;
        const goalId = await db.addWeeklyGoal(req.userId, title, description, target, unit);
        res.json({ goalId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Hydration tracking routes
router.post('/hydration/track', authenticateUser, async (req, res) => {
    try {
        const { amount, timestamp } = req.body;
        const entryId = await db.addHydrationEntry(req.userId, amount, timestamp);
        res.json({ entryId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/hydration/daily', authenticateUser, async (req, res) => {
    try {
        const date = req.query.date || new Date().toISOString().split('T')[0];
        const total = await db.getDailyHydration(req.userId, date);
        res.json({ total });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Achievement routes
router.get('/achievements', authenticateUser, async (req, res) => {
    try {
        const achievements = await db.getAchievements(req.userId);
        res.json(achievements);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get monthly hydration data
router.get('/hydration/monthly', authenticateUser, async (req, res) => {
    try {
        const monthlyData = await db.getMonthlyHydration(req.session.userId);
        res.json(monthlyData);
    } catch (error) {
        console.error('Error getting monthly hydration:', error);
        res.status(500).json({ error: 'Failed to get monthly hydration data' });
    }
});

// Get peak hydration times
router.get('/hydration/peak-times', authenticateUser, async (req, res) => {
    try {
        const peakTimes = await db.getPeakHydrationTimes(req.session.userId);
        res.json(peakTimes);
    } catch (error) {
        console.error('Error getting peak times:', error);
        res.status(500).json({ error: 'Failed to get peak hydration times' });
    }
});

// Get weekly patterns
router.get('/hydration/weekly-patterns', authenticateUser, async (req, res) => {
    try {
        const patterns = await db.getWeeklyPatterns(req.session.userId);
        res.json(patterns);
    } catch (error) {
        console.error('Error getting weekly patterns:', error);
        res.status(500).json({ error: 'Failed to get weekly patterns' });
    }
});

// Get user streaks
router.get('/hydration/streaks', authenticateUser, async (req, res) => {
    try {
        const streaks = await db.getUserStreaks(req.session.userId);
        res.json(streaks);
    } catch (error) {
        console.error('Error getting streaks:', error);
        res.status(500).json({ error: 'Failed to get streak data' });
    }
});

// Get achievement progress
router.get('/achievements', authenticateUser, async (req, res) => {
    try {
        const achievements = await db.getAchievementProgress(req.session.userId);
        res.json(achievements);
    } catch (error) {
        console.error('Error getting achievements:', error);
        res.status(500).json({ error: 'Failed to get achievements' });
    }
});

// Update achievement progress
router.post('/achievements/:id/progress', authenticateUser, async (req, res) => {
    try {
        const { id } = req.params;
        const { progress } = req.body;
        
        if (typeof progress !== 'number') {
            return res.status(400).json({ error: 'Progress must be a number' });
        }

        await db.updateAchievementProgress(req.session.userId, id, progress);
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating achievement progress:', error);
        res.status(500).json({ error: 'Failed to update achievement progress' });
    }
});

module.exports = router; 