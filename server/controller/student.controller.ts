import { User, Course, Group, Quiz, CourseRegistration, GroupRegistration, QuizQuestion, QuizResult } from '../model/model';
import { IUser } from '../model/schema/user.schema';
import { ICourse } from '../model/schema/course.schema';
import { IGroup } from '../model/schema/group.schema';
import { IQuiz } from '../model/schema/quiz.schema';
import { IQuizQuestion } from '../model/schema/quizQuestion.schema';
import { IQuizResult } from '../model/schema/quizResult.schema';
import { ICourseRegistration } from '../model/schema/courseRegistration.schema';
import { IGroupRegistration } from '../model/schema/groupRegistration.schema';
import { JwtPayload } from '../types/auth.types';
import ResponseApi from '../util/ApiResponse.util';
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const register = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    if (password.length < 6 || password.length > 20) {
      return ResponseApi(
        res,
        400,
        'Password must be at least 6 and at most 20 characters'
      );
    }

    const existingUser = (await User.findOne({
      email: email.toLowerCase(),
    })) as IUser | null;
    if (existingUser) {
      return ResponseApi(res, 400, 'User already exists');
    }

    const genSalt = await bcrypt.genSalt(5);
    const hashedPassword = await bcrypt.hash(password, genSalt);

    const newStudent: IUser = new User({
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'student'
    });
    await newStudent.save();

    return ResponseApi(res, 201, 'Student registered successfully');
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while registering the student'
    );
  }
};

const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    const existingStudent = (await User.findOne({
      email: email.toLowerCase(),
      role: 'student'
    })) as IUser | null;
    if (!existingStudent) {
      return ResponseApi(res, 400, 'Student does not exist');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      existingStudent.password
    );
    if (!isPasswordValid) {
      return ResponseApi(res, 400, 'Invalid password');
    }

    if (!process.env.JWT_SECRET_KEY) {
      return ResponseApi(res, 500, 'JWT secret key is not defined');
    }

    const payload: JwtPayload = {
      _id: String(existingStudent._id),
      role: 'student',
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET_KEY,
      { expiresIn: '30d' }
    );

    return ResponseApi(res, 200, 'Student logged in successfully', token);
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while logging in the student'
    );
  }
};

const getAllCourses = async (req: Request, res: Response) => {
  try {
    const courses = await Course.find({}) as ICourse[];
    return ResponseApi(res, 200, 'Courses retrieved successfully', courses);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting courses');
  }
};

const registerForCourse = async (req: Request, res: Response) => {
  try {
    const { courseId } = req.body;
    const { _id } = req.body; // Student ID from middleware

    if (!courseId) {
      return ResponseApi(res, 400, 'Course ID is required');
    }

    // Verify course exists
    const course = await Course.findById(courseId);
    if (!course) {
      return ResponseApi(res, 404, 'Course not found');
    }

    // Check if already registered
    const existingRegistration = await CourseRegistration.findOne({
      courseId,
      userId: _id
    });
    if (existingRegistration) {
      return ResponseApi(res, 400, 'Already registered for this course');
    }

    const newRegistration = new CourseRegistration({
      courseId,
      userId: _id
    });
    await newRegistration.save();

    const populatedRegistration = await CourseRegistration.findById(newRegistration._id)
      .populate('courseId', 'courseName courseCode courseCredit')
      .populate('userId', 'email');

    return ResponseApi(res, 201, 'Course registration successful', populatedRegistration);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while registering for the course');
  }
};

const getMyCourses = async (req: Request, res: Response) => {
  try {
    const { _id } = req.body; // Student ID from middleware

    const registrations = await CourseRegistration.find({ userId: _id })
      .populate('courseId', 'courseName courseCode courseCredit') as ICourseRegistration[];

    const courses = registrations.map(registration => registration.courseId);

    return ResponseApi(res, 200, 'My courses retrieved successfully', courses);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting your courses');
  }
};

const getAvailableGroups = async (req: Request, res: Response) => {
  try {
    const { _id } = req.body; // Student ID from middleware

    // Get courses the student is registered for
    const registrations = await CourseRegistration.find({ userId: _id });
    const courseIds = registrations.map(reg => reg.courseId);

    // Get groups for those courses that have registration open
    const groups = await Group.find({
      courseId: { $in: courseIds },
      registrationOpen: true
    })
      .populate('courseId', 'courseName courseCode')
      .populate('facultyId', 'email') as IGroup[];

    return ResponseApi(res, 200, 'Available groups retrieved successfully', groups);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting available groups');
  }
};

const registerForGroup = async (req: Request, res: Response) => {
  try {
    const { groupId } = req.body;
    const { _id } = req.body; // Student ID from middleware

    if (!groupId) {
      return ResponseApi(res, 400, 'Group ID is required');
    }

    // Verify group exists and registration is open
    const group = await Group.findById(groupId).populate('courseId');
    if (!group) {
      return ResponseApi(res, 404, 'Group not found');
    }

    if (!group.registrationOpen) {
      return ResponseApi(res, 400, 'Registration is not open for this group');
    }

    // Verify student is registered for the course
    const courseRegistration = await CourseRegistration.findOne({
      courseId: group.courseId,
      userId: _id
    });
    if (!courseRegistration) {
      return ResponseApi(res, 400, 'You must be registered for the course first');
    }

    // Check if already registered for this group
    const existingRegistration = await GroupRegistration.findOne({
      groupId,
      userId: _id
    });
    if (existingRegistration) {
      return ResponseApi(res, 400, 'Already registered for this group');
    }

    const newRegistration = new GroupRegistration({
      groupId,
      userId: _id
    });
    await newRegistration.save();

    const populatedRegistration = await GroupRegistration.findById(newRegistration._id)
      .populate('groupId', 'name')
      .populate('userId', 'email');

    return ResponseApi(res, 201, 'Group registration successful', populatedRegistration);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while registering for the group');
  }
};

const getMyGroups = async (req: Request, res: Response) => {
  try {
    const { _id } = req.body; // Student ID from middleware

    const registrations = await GroupRegistration.find({ userId: _id })
      .populate({
        path: 'groupId',
        populate: {
          path: 'courseId',
          select: 'courseName courseCode'
        }
      })
      .populate({
        path: 'groupId',
        populate: {
          path: 'facultyId',
          select: 'email'
        }
      }) as IGroupRegistration[];

    const groups = registrations.map(registration => registration.groupId);

    return ResponseApi(res, 200, 'My groups retrieved successfully', groups);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting your groups');
  }
};

const getAvailableQuizzes = async (req: Request, res: Response) => {
  try {
    const { _id } = req.body; // Student ID from middleware

    // Get groups the student is registered for
    const registrations = await GroupRegistration.find({ userId: _id });
    const groupIds = registrations.map(reg => reg.groupId);

    // Get quizzes for those groups
    const quizzes = await Quiz.find({
      groupId: { $in: groupIds }
    })
      .populate('groupId', 'name')
      .populate('facultyId', 'email') as IQuiz[];

    return ResponseApi(res, 200, 'Available quizzes retrieved successfully', quizzes);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting available quizzes');
  }
};

const getQuizQuestions = async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { _id } = req.body; // Student ID from middleware

    // Verify student has access to this quiz
    const quiz = await Quiz.findById(quizId);
    if (!quiz) {
      return ResponseApi(res, 404, 'Quiz not found');
    }

    // Check if student is registered for the group
    const groupRegistration = await GroupRegistration.findOne({
      groupId: quiz.groupId,
      userId: _id
    });
    if (!groupRegistration) {
      return ResponseApi(res, 403, 'You do not have access to this quiz');
    }

    // Get questions without answers for student
    const questions = await QuizQuestion.find({ quizId }).select('-answer') as IQuizQuestion[];

    return ResponseApi(res, 200, 'Quiz questions retrieved successfully', questions);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting quiz questions');
  }
};

const submitQuiz = async (req: Request, res: Response) => {
  try {
    const { quizId, answers } = req.body; // answers should be an array of { questionId, selectedAnswer }
    const { _id } = req.body; // Student ID from middleware

    if (!quizId || !answers || !Array.isArray(answers)) {
      return ResponseApi(res, 400, 'Quiz ID and answers array are required');
    }

    // Verify student has access to this quiz
    const quiz = await Quiz.findById(quizId);
    if (!quiz) {
      return ResponseApi(res, 404, 'Quiz not found');
    }

    const groupRegistration = await GroupRegistration.findOne({
      groupId: quiz.groupId,
      userId: _id
    });
    if (!groupRegistration) {
      return ResponseApi(res, 403, 'You do not have access to this quiz');
    }

    // Check if already submitted
    const existingResult = await QuizResult.findOne({
      quizId,
      userId: _id
    });
    if (existingResult) {
      return ResponseApi(res, 400, 'Quiz already submitted');
    }

    // Get all questions with correct answers
    const questions = await QuizQuestion.find({ quizId }) as IQuizQuestion[];
    
    // Calculate score
    let correctAnswers = 0;
    let totalQuestions = questions.length;

    for (const answer of answers) {
      const question = questions.find(q => String(q._id) === answer.questionId);
      if (question && question.answer === answer.selectedAnswer) {
        correctAnswers++;
      }
    }

    const marks = Math.round((correctAnswers / totalQuestions) * 100);

    // Save result
    const quizResult = new QuizResult({
      quizId,
      userId: _id,
      marks
    });
    await quizResult.save();

    const populatedResult = await QuizResult.findById(quizResult._id)
      .populate('quizId', 'name')
      .populate('userId', 'email');

    return ResponseApi(res, 201, 'Quiz submitted successfully', {
      result: populatedResult,
      score: `${correctAnswers}/${totalQuestions}`,
      percentage: marks
    });
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while submitting the quiz');
  }
};

const getMyQuizResults = async (req: Request, res: Response) => {
  try {
    const { _id } = req.body; // Student ID from middleware

    const results = await QuizResult.find({ userId: _id })
      .populate('quizId', 'name')
      .populate('userId', 'email') as IQuizResult[];

    return ResponseApi(res, 200, 'Quiz results retrieved successfully', results);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting your quiz results');
  }
};

const verifyStudent = async (req: Request, res: Response) => {
  try {
    const { _id, role } = req.body;

    if (_id === undefined || role === undefined) {
      return ResponseApi(res, 403, 'Forbidden');
    }

    const student = await User.findById(_id).select('-password');
    if (!student || student.role !== 'student') {
      return ResponseApi(res, 400, "No Such Student")
    }

    return ResponseApi(res, 200, 'Student verified successfully', student);
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while verifying the student'
    )
  }
}

const updateProfile = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const { _id, role } = req.body; // Provided by studentMiddleware

    if (!email) {
      return ResponseApi(res, 400, 'Email is required');
    }

    if (role !== 'student') {
      return ResponseApi(res, 403, 'Forbidden: Student access required');
    }

    await User.findByIdAndUpdate(
      _id,
      {
        email: email.toLowerCase(),
      }
    )

    return ResponseApi(res, 200, 'Student profile updated successfully');
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while updating the student profile');
  }
}

const changePassword = async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const { _id, role } = req.body; // Provided by studentMiddleware

    if (!currentPassword || !newPassword) {
      return ResponseApi(res, 400, 'Current password and new password are required');
    }

    if (newPassword.length < 6 || newPassword.length > 20) {
      return ResponseApi(res, 400, 'New password must be at least 6 and at most 20 characters');
    }

    if (role !== 'student') {
      return ResponseApi(res, 403, 'Forbidden: Student access required');
    }

    const student = await User.findById(_id);
    if (!student) {
      return ResponseApi(res, 404, 'Student not found');
    }

    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, student.password);
    if (!isCurrentPasswordValid) {
      return ResponseApi(res, 400, 'Current password is incorrect');
    }

    const genSalt = await bcrypt.genSalt(5);
    const hashedNewPassword = await bcrypt.hash(newPassword, genSalt);

    await User.findByIdAndUpdate(_id, { password: hashedNewPassword });

    return ResponseApi(res, 200, 'Password changed successfully');
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while changing the password');
  }
}

export {
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
};
