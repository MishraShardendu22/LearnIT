import { User, Course, Group, Quiz, CourseRegistration, GroupRegistration, QuizQuestion, QuizResult } from '../model/model';
import { IUser } from '../model/schema/user.schema';
import { ICourse } from '../model/schema/course.schema';
import { IGroup } from '../model/schema/group.schema';
import { IQuiz } from '../model/schema/quiz.schema';
import { JwtPayload } from '../types/auth.types';
import ResponseApi from '../util/ApiResponse.util';
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const register = async (req: Request, res: Response) => {
  try {
    const { email, password, adminPassword } = req.body;

    if(process.env.ADMIN_PASSWORD !== adminPassword){
      return ResponseApi(res, 400, 'Invalid Admin Password');
    }

    if (!email || !password || !adminPassword) {
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    // Check if email ends with @iiitdwd.ac.in
    if (!email.toLowerCase().endsWith('@iiitdwd.ac.in')) {
      return ResponseApi(res, 400, 'Only @iiitdwd.ac.in email addresses are allowed');
    }

    if (password.length < 6 || password.length > 20) {
      return ResponseApi(
        res,
        400,
        'Password must be at least 6 and at most 20 characters'
      );
    }

    const existingAdmin = (await User.findOne({
      email: email.toLowerCase(),
      role: 'admin'
    })) as IUser | null;
    if (existingAdmin) {
      return ResponseApi(res, 400, 'Admin already exists');
    }

    const genSalt = await bcrypt.genSalt(5);
    const hashedPassword = await bcrypt.hash(password, genSalt);

    const newAdmin: IUser = new User({
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'admin'
    });
    await newAdmin.save();

    return ResponseApi(res, 201, 'Admin registered successfully');
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while registering the admin'
    );
  }
};

const login = async (req: Request, res: Response) => {
  try {
    const { email, password, adminPassword  } = req.body;

    if(!adminPassword){
      return ResponseApi(res, 400, 'Admin Password is required');
    }

    if(process.env.ADMIN_PASSWORD !== adminPassword){
      return ResponseApi(res, 400, 'Invalid Admin Password');
    }

    if (!email || !password) {
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    const existingAdmin = (await User.findOne({
      email: email.toLowerCase(),
      role: 'admin'
    })) as IUser | null;
    if (!existingAdmin) {
      return ResponseApi(res, 400, 'Admin does not exist');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      existingAdmin.password
    );
    if (!isPasswordValid) {
      return ResponseApi(res, 400, 'Invalid password');
    }

    if (!process.env.JWT_SECRET_KEY) {
      return ResponseApi(res, 500, 'JWT secret key is not defined');
    }

    const payload: JwtPayload = {
      _id: String(existingAdmin._id),
      role: 'admin',
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET_KEY,
      { expiresIn: '30d' }
    );

    return ResponseApi(res, 200, 'Admin logged in successfully', token);
  } catch (error) {
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while logging in the admin'
    );
  }
};

const getUsers = async (req: Request, res: Response) => {
  try{
    const users = await User.find({}).select('-password') as IUser[];
    return ResponseApi(res, 200, 'Users retrieved successfully', users);
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting the users');
  }
}

const deleteUser = async (req: Request, res: Response) => {
  try{
    const { userId } = req.body;

    if(!userId){
      return ResponseApi(res, 400, 'User ID is required');
    }

    const user = await User.findByIdAndDelete(userId) as IUser | null;
    if(!user){
      return ResponseApi(res, 404, 'User not found');
    }

    // Clean up related data
    await CourseRegistration.deleteMany({ userId });
    await GroupRegistration.deleteMany({ userId });
    await QuizResult.deleteMany({ userId });

    return ResponseApi(res, 200, 'User deleted successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while deleting the user');
  }
}

const getCourses = async (req: Request, res: Response) => {
  try{
    const courses = await Course.find({}) as ICourse[];
    return ResponseApi(res, 200, 'Courses retrieved successfully', courses);
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting the courses');
  }
}

const deleteCourse = async (req: Request, res: Response) => {
  try{
    const { courseId } = req.body;

    if(!courseId){
      return ResponseApi(res, 400, 'Course ID is required');
    }

    const course = await Course.findByIdAndDelete(courseId) as ICourse | null;
    if(!course){
      return ResponseApi(res, 404, 'Course not found');
    }

    // Clean up related data
    await CourseRegistration.deleteMany({ courseId });
    await Group.deleteMany({ courseId });

    return ResponseApi(res, 200, 'Course deleted successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while deleting the course');
  }
}

const getGroups = async (req: Request, res: Response) => {
  try{
    const groups = await Group.find({})
      .populate('courseId', 'courseName courseCode')
      .populate('facultyId', 'email') as IGroup[];
    return ResponseApi(res, 200, 'Groups retrieved successfully', groups);
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting the groups');
  }
}

const deleteGroup = async (req: Request, res: Response) => {
  try{
    const { groupId } = req.body;

    if(!groupId){
      return ResponseApi(res, 400, 'Group ID is required');
    }

    const group = await Group.findByIdAndDelete(groupId) as IGroup | null;
    if(!group){
      return ResponseApi(res, 404, 'Group not found');
    }

    // Clean up related data
    await GroupRegistration.deleteMany({ groupId });
    await Quiz.deleteMany({ groupId });

    return ResponseApi(res, 200, 'Group deleted successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while deleting the group');
  }
}

const getQuizzes = async (req: Request, res: Response) => {
  try{
    const quizzes = await Quiz.find({})
      .populate('facultyId', 'email')
      .populate('groupId', 'name') as IQuiz[];
    return ResponseApi(res, 200, 'Quizzes retrieved successfully', quizzes);
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting the quizzes');
  }
}

const deleteQuiz = async (req: Request, res: Response) => {
  try{
    const { quizId } = req.body;

    if(!quizId){
      return ResponseApi(res, 400, 'Quiz ID is required');
    }

    const quiz = await Quiz.findByIdAndDelete(quizId) as IQuiz | null;
    if(!quiz){
      return ResponseApi(res, 404, 'Quiz not found');
    }

    // Clean up related data
    await QuizQuestion.deleteMany({ quizId });
    await QuizResult.deleteMany({ quizId });

    return ResponseApi(res, 200, 'Quiz deleted successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while deleting the quiz');
  }
}

const getAnalytics = async (req: Request, res: Response) => {
  try{
    const totalUsers = await User.countDocuments();
    const students = await User.countDocuments({ role: 'student' });
    const faculty = await User.countDocuments({ role: 'faculty' });
    const admins = await User.countDocuments({ role: 'admin' });
    const courses = await Course.countDocuments();
    const groups = await Group.countDocuments();
    const quizzes = await Quiz.countDocuments();
    const courseRegistrations = await CourseRegistration.countDocuments();
    const groupRegistrations = await GroupRegistration.countDocuments();

    return ResponseApi(res, 200, 'Analytics retrieved successfully', {
      totalUsers,
      students,
      faculty,
      admins,
      courses,
      groups,
      quizzes,
      courseRegistrations,
      groupRegistrations,
    });
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while getting the analytics');
  }
}

const verifyAdmin = async (req: Request,res: Response) => {
  try{
    const { _id,role } = req.body;

    if(_id === undefined || role === undefined){
      return ResponseApi(res,403,'Forbidden');
    }

    const admin = await User.findById(_id).select('-password');
    if(!admin || admin.role !== 'admin'){
      return ResponseApi(res,400,"No Such Admin")
    }

    return ResponseApi(res,200,'Admin verified successfully',admin);
  }catch(error){
    return ResponseApi(
      res,
      500,
      error instanceof Error
        ? error.message
        : 'An unknown error occurred while verifying the admin'
    )
  }
}

const resetPassword = async (req: Request, res: Response) => {
  try{
    const { email, password } = req.body;
    // _id and role are provided by adminMiddleware

    if(!email || !password){
      return ResponseApi(res, 400, 'Please provide all required fields');
    }

    if(password.length < 6 || password.length > 20){
      return ResponseApi(res, 400, 'Password must be at least 6 and at most 20 characters');
    }

    const existingAdmin = await User.findOne({ email, role: 'admin' });
    if(!existingAdmin){
      return ResponseApi(res, 404, 'Admin not found');
    }

    const genSalt = await bcrypt.genSalt(5);
    const hashedPassword = await bcrypt.hash(password, genSalt);

    await User.findByIdAndUpdate(existingAdmin._id, { password: hashedPassword });

    return ResponseApi(res, 200, 'Password reset successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while resetting the password');
  }
}

const updateUser = async (req: Request, res: Response) => {
  try{
    const { userId, email } = req.body;
    // _id and role are provided by adminMiddleware

    if(!userId || !email){
      return ResponseApi(res, 400, 'User ID and email are required');
    }

    await User.findByIdAndUpdate(
      {_id : userId},
      {
        email: email.toLowerCase(),
      }
    )

    return ResponseApi(res, 200, 'User updated successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while updating the user');
  }
}

const updateAdminProfile = async (req: Request, res: Response) => {
  try{
    const { email } = req.body;
    const { _id, role } = req.body; // Provided by adminMiddleware

    if(!email){
      return ResponseApi(res, 400, 'Email is required');
    }

    // Verify the user is actually an admin (additional security check)
    if(role !== 'admin'){
      return ResponseApi(res, 403, 'Forbidden: Admin access required');
    }

    await User.findByIdAndUpdate(
      _id,
      {
        email: email.toLowerCase(),
      }
    )

    return ResponseApi(res, 200, 'Admin profile updated successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while updating the admin profile');
  }
}

const changeAdminPassword = async (req: Request, res: Response) => {
  try{
    const { currentPassword, newPassword } = req.body;
    const { _id, role } = req.body; // Provided by adminMiddleware

    if(!currentPassword || !newPassword){
      return ResponseApi(res, 400, 'Current password and new password are required');
    }

    if(newPassword.length < 6 || newPassword.length > 20){
      return ResponseApi(res, 400, 'New password must be at least 6 and at most 20 characters');
    }

    // Verify the user is actually an admin (additional security check)
    if(role !== 'admin'){
      return ResponseApi(res, 403, 'Forbidden: Admin access required');
    }

    const admin = await User.findById(_id);
    if(!admin){
      return ResponseApi(res, 404, 'Admin not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, admin.password);
    if(!isCurrentPasswordValid){
      return ResponseApi(res, 400, 'Current password is incorrect');
    }

    const genSalt = await bcrypt.genSalt(5);
    const hashedNewPassword = await bcrypt.hash(newPassword, genSalt);

    await User.findByIdAndUpdate(_id, { password: hashedNewPassword });

    return ResponseApi(res, 200, 'Password changed successfully');
  }catch(error){
    return ResponseApi(res, 500, error instanceof Error ? error.message : 'An unknown error occurred while changing the password');
  }
}

export {
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
};
