import { User, Course, Group, Quiz, CourseRegistration, GroupRegistration, QuizQuestion, QuizResult } from '../model/model';
import { IUser } from '../model/schema/user.schema';
import { ICourse } from '../model/schema/course.schema';
import { IGroup } from '../model/schema/group.schema';
import { IQuiz } from '../model/schema/quiz.schema';
import { IQuizQuestion } from '../model/schema/quizQuestion.schema';
import { IQuizResult } from '../model/schema/quizResult.schema';
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

    const newFaculty: IUser = new User({
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'faculty'
    });
    await newFaculty.save();

    return ResponseApi(res, 201, 'Faculty registered successfully');
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while registering the faculty'
    );
  }
};

const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    const existingFaculty = (await User.findOne({
      email: email.toLowerCase(),
      role: 'faculty'
    })) as IUser | null;
    if (!existingFaculty) {
      return ResponseApi(res, 400, 'Faculty does not exist');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      existingFaculty.password
    );
    if (!isPasswordValid) {
      return ResponseApi(res, 400, 'Invalid password');
    }

    if (!process.env.JWT_SECRET_KEY) {
      return ResponseApi(res, 500, 'JWT secret key is not defined');
    }

    const payload: JwtPayload = {
      _id: String(existingFaculty._id),
      role: 'faculty',
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET_KEY,
      { expiresIn: '30d' }
    );

    return ResponseApi(res, 200, 'Faculty logged in successfully', token);
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while logging in the faculty'
    );
  }
};

const createCourse = async (req: Request, res: Response) => {
  try {
    const { courseCode, courseCredit, courseName } = req.body;
    // _id and role are provided by facultyMiddleware

    if (!courseCode || !courseCredit || !courseName) {
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    if (courseCredit < 1) {
      return ResponseApi(res, 400, 'Course credits must be at least 1');
    }

    const existingCourse = await Course.findOne({ courseCode });
    if (existingCourse) {
      return ResponseApi(res, 400, 'Course with this code already exists');
    }

    const newCourse = new Course({
      courseCode,
      courseCredit,
      courseName
    });
    await newCourse.save();

    return ResponseApi(res, 201, 'Course created successfully', newCourse);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while creating the course');
  }
};

const createGroup = async (req: Request, res: Response) => {
  try {
    const { name, courseId, registrationOpen } = req.body;
    const { _id } = req.body; // Faculty ID from middleware

    if (!name || !courseId) {
      return ResponseApi(res, 400, 'Please provide group name and course ID');
    }

    // Verify course exists
    const course = await Course.findById(courseId);
    if (!course) {
      return ResponseApi(res, 404, 'Course not found');
    }

    const newGroup = new Group({
      name,
      courseId,
      facultyId: _id,
      registrationOpen: registrationOpen || false
    });
    await newGroup.save();

    const populatedGroup = await Group.findById(newGroup._id)
      .populate('courseId', 'courseName courseCode')
      .populate('facultyId', 'email');

    return ResponseApi(res, 201, 'Group created successfully', populatedGroup);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while creating the group');
  }
};

const getMyGroups = async (req: Request, res: Response) => {
  try {
    const { _id } = req.body; // Faculty ID from middleware

    const groups = await Group.find({ facultyId: _id })
      .populate('courseId', 'courseName courseCode') as IGroup[];

    return ResponseApi(res, 200, 'Groups retrieved successfully', groups);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting groups');
  }
};

const updateGroup = async (req: Request, res: Response) => {
  try {
    const { groupId, name, registrationOpen } = req.body;
    const { _id } = req.body; // Faculty ID from middleware

    if (!groupId) {
      return ResponseApi(res, 400, 'Group ID is required');
    }

    // Verify faculty owns this group
    const group = await Group.findOne({ _id: groupId, facultyId: _id });
    if (!group) {
      return ResponseApi(res, 404, 'Group not found or you do not have permission to modify it');
    }

    const updateData: any = {};
    if (name !== undefined) updateData.name = name;
    if (registrationOpen !== undefined) updateData.registrationOpen = registrationOpen;

    const updatedGroup = await Group.findByIdAndUpdate(groupId, updateData, { new: true })
      .populate('courseId', 'courseName courseCode');

    return ResponseApi(res, 200, 'Group updated successfully', updatedGroup);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while updating the group');
  }
};

const createQuiz = async (req: Request, res: Response) => {
  try {
    const { name, groupId } = req.body;
    const { _id } = req.body; // Faculty ID from middleware

    if (!name || !groupId) {
      return ResponseApi(res, 400, 'Please provide quiz name and group ID');
    }

    // Verify faculty owns this group
    const group = await Group.findOne({ _id: groupId, facultyId: _id });
    if (!group) {
      return ResponseApi(res, 404, 'Group not found or you do not have permission to create quiz in this group');
    }

    const newQuiz = new Quiz({
      name,
      facultyId: _id,
      groupId
    });
    await newQuiz.save();

    const populatedQuiz = await Quiz.findById(newQuiz._id)
      .populate('groupId', 'name')
      .populate('facultyId', 'email');

    return ResponseApi(res, 201, 'Quiz created successfully', populatedQuiz);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while creating the quiz');
  }
};

const getMyQuizzes = async (req: Request, res: Response) => {
  try {
    const { _id } = req.body; // Faculty ID from middleware

    const quizzes = await Quiz.find({ facultyId: _id })
      .populate('groupId', 'name')
      .populate('facultyId', 'email') as IQuiz[];

    return ResponseApi(res, 200, 'Quizzes retrieved successfully', quizzes);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting quizzes');
  }
};

const addQuizQuestion = async (req: Request, res: Response) => {
  try {
    const { quizId, questionText, questionImage, options, answer } = req.body;
    const { _id } = req.body; // Faculty ID from middleware

    if (!quizId || !questionText || !options || !answer) {
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    // Verify faculty owns this quiz
    const quiz = await Quiz.findOne({ _id: quizId, facultyId: _id });
    if (!quiz) {
      return ResponseApi(res, 404, 'Quiz not found or you do not have permission to modify it');
    }

    if (!Array.isArray(options) || options.length < 2) {
      return ResponseApi(res, 400, 'At least 2 options are required');
    }

    if (!options.includes(answer)) {
      return ResponseApi(res, 400, 'Answer must be one of the provided options');
    }

    const newQuestion = new QuizQuestion({
      quizId,
      questionText,
      questionImage,
      options,
      answer
    });
    await newQuestion.save();

    return ResponseApi(res, 201, 'Question added successfully', newQuestion);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while adding the question');
  }
};

const getQuizQuestions = async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { _id } = req.body; // Faculty ID from middleware

    // Verify faculty owns this quiz
    const quiz = await Quiz.findOne({ _id: quizId, facultyId: _id });
    if (!quiz) {
      return ResponseApi(res, 404, 'Quiz not found or you do not have permission to view it');
    }

    const questions = await QuizQuestion.find({ quizId }) as IQuizQuestion[];

    return ResponseApi(res, 200, 'Quiz questions retrieved successfully', questions);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting quiz questions');
  }
};

const getQuizResults = async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { _id } = req.body; // Faculty ID from middleware

    // Verify faculty owns this quiz
    const quiz = await Quiz.findOne({ _id: quizId, facultyId: _id });
    if (!quiz) {
      return ResponseApi(res, 404, 'Quiz not found or you do not have permission to view results');
    }

    const results = await QuizResult.find({ quizId })
      .populate('userId', 'email')
      .populate('quizId', 'name') as IQuizResult[];

    return ResponseApi(res, 200, 'Quiz results retrieved successfully', results);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting quiz results');
  }
};

const getGroupRegistrations = async (req: Request, res: Response) => {
  try {
    const { groupId } = req.params;
    const { _id } = req.body; // Faculty ID from middleware

    // Verify faculty owns this group
    const group = await Group.findOne({ _id: groupId, facultyId: _id });
    if (!group) {
      return ResponseApi(res, 404, 'Group not found or you do not have permission to view registrations');
    }

    const registrations = await GroupRegistration.find({ groupId })
      .populate('userId', 'email')
      .populate('groupId', 'name');

    return ResponseApi(res, 200, 'Group registrations retrieved successfully', registrations);
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting group registrations');
  }
};

const verifyFaculty = async (req: Request, res: Response) => {
  try {
    const { _id, role } = req.body;

    if (_id === undefined || role === undefined) {
      return ResponseApi(res, 403, 'Forbidden');
    }

    const faculty = await User.findById(_id).select('-password');
    if (!faculty || faculty.role !== 'faculty') {
      return ResponseApi(res, 400, "No Such Faculty")
    }

    return ResponseApi(res, 200, 'Faculty verified successfully', faculty);
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while verifying the faculty'
    )
  }
}

const updateProfile = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const { _id, role } = req.body; // Provided by facultyMiddleware

    if (!email) {
      return ResponseApi(res, 400, 'Email is required');
    }

    if (role !== 'faculty') {
      return ResponseApi(res, 403, 'Forbidden: Faculty access required');
    }

    await User.findByIdAndUpdate(
      _id,
      {
        email: email.toLowerCase(),
      }
    )

    return ResponseApi(res, 200, 'Faculty profile updated successfully');
  } catch (error) {
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while updating the faculty profile');
  }
}

const changePassword = async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const { _id, role } = req.body; // Provided by facultyMiddleware

    if (!currentPassword || !newPassword) {
      return ResponseApi(res, 400, 'Current password and new password are required');
    }

    if (newPassword.length < 6 || newPassword.length > 20) {
      return ResponseApi(res, 400, 'New password must be at least 6 and at most 20 characters');
    }

    if (role !== 'faculty') {
      return ResponseApi(res, 403, 'Forbidden: Faculty access required');
    }

    const faculty = await User.findById(_id);
    if (!faculty) {
      return ResponseApi(res, 404, 'Faculty not found');
    }

    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, faculty.password);
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
};
