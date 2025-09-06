import {
  register,
  login,
  getAllCourses,
  registerForCourse,
  getMyCourses,
  getAvailableGroups,
  registerForGroup,
  getMyGroups,
  getAvailableQuizzes,
  getQuizQuestions,
  submitQuiz,
  getMyQuizResults,
  verifyStudent,
  updateProfile,
  changePassword,
} from '../../controller/student.controller';

import { Router } from 'express';
import { studentMiddleware } from '../../middleware/student.middleware';
const router = Router();

// Public routes (no middleware required)
router.post('/login', login);
router.post('/register', register);

// Course-related routes
router.get('/courses', getAllCourses);

// Protected routes (require student middleware)
router.get('/verify', studentMiddleware, verifyStudent);

// Course registration routes
router.post('/course/register', studentMiddleware, registerForCourse);
router.get('/courses/my', studentMiddleware, getMyCourses);

// Group registration routes
router.get('/groups/available', studentMiddleware, getAvailableGroups);
router.post('/group/register', studentMiddleware, registerForGroup);
router.get('/groups/my', studentMiddleware, getMyGroups);

// Quiz routes
router.get('/quizzes/available', studentMiddleware, getAvailableQuizzes);
router.get('/quiz/:quizId/questions', studentMiddleware, getQuizQuestions);
router.post('/quiz/submit', studentMiddleware, submitQuiz);
router.get('/quiz/results', studentMiddleware, getMyQuizResults);

// Student profile management routes
router.put('/profile', studentMiddleware, updateProfile);
router.put('/change-password', studentMiddleware, changePassword);

export default router;
