import {
  register,
  login,
  createCourse,
  createGroup,
  getMyGroups,
  updateGroup,
  createQuiz,
  getMyQuizzes,
  addQuizQuestion,
  getQuizQuestions,
  getQuizResults,
  getGroupRegistrations,
  verifyFaculty,
  updateProfile,
  changePassword,
} from '../../controller/faculty.controller';

import { Router } from 'express';
import { facultyMiddleware } from '../../middleware/faculty.middleware';
const router = Router();

// Public routes (no middleware required)
router.post('/login', login);
router.post('/register', register);

// Protected routes (require faculty middleware)
router.get('/verify', facultyMiddleware, verifyFaculty);

// Course management routes
router.post('/course', facultyMiddleware, createCourse);

// Group management routes
router.post('/group', facultyMiddleware, createGroup);
router.get('/groups', facultyMiddleware, getMyGroups);
router.put('/group', facultyMiddleware, updateGroup);
router.get('/group/:groupId/registrations', facultyMiddleware, getGroupRegistrations);

// Quiz management routes
router.post('/quiz', facultyMiddleware, createQuiz);
router.get('/quizzes', facultyMiddleware, getMyQuizzes);
router.post('/quiz/question', facultyMiddleware, addQuizQuestion);
router.get('/quiz/:quizId/questions', facultyMiddleware, getQuizQuestions);
router.get('/quiz/:quizId/results', facultyMiddleware, getQuizResults);

// Faculty profile management routes
router.put('/profile', facultyMiddleware, updateProfile);
router.put('/change-password', facultyMiddleware, changePassword);

export default router;
