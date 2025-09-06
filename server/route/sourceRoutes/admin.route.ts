import {
  register,
  login,
  getUsers,
  deleteUser,
  getCourses,
  deleteCourse,
  getGroups,
  deleteGroup,
  getQuizzes,
  deleteQuiz,
  getAnalytics,
  verifyAdmin,
  resetPassword,
  updateUser,
  updateAdminProfile,
  changeAdminPassword,
} from '../../controller/admin.controller';

import { Router } from 'express';
import { adminMiddleware } from '../../middleware/admin.middleware';
const router = Router();

// Public routes (no middleware required)
router.post('/login', login);
router.post('/register', register);
router.post('/resetPassword', resetPassword);

// Protected routes (require admin middleware)
router.get('/verify', adminMiddleware, verifyAdmin);
router.get('/analytics', adminMiddleware, getAnalytics);

// User management routes
router.get('/users', adminMiddleware, getUsers);
router.delete('/user', adminMiddleware, deleteUser);
router.put('/user', adminMiddleware, updateUser);

// Course management routes
router.get('/courses', adminMiddleware, getCourses);
router.delete('/course', adminMiddleware, deleteCourse);

// Group management routes
router.get('/groups', adminMiddleware, getGroups);
router.delete('/group', adminMiddleware, deleteGroup);

// Quiz management routes
router.get('/quizzes', adminMiddleware, getQuizzes);
router.delete('/quiz', adminMiddleware, deleteQuiz);

// Admin profile management routes
router.put('/profile', adminMiddleware, updateAdminProfile);
router.put('/change-password', adminMiddleware, changeAdminPassword);

export default router;
