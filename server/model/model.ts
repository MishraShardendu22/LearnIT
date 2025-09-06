import mongoose, { Model } from 'mongoose';
import { UserSchema, IUser } from './schema/user.schema';
import { QuizSchema, IQuiz } from './schema/quiz.schema';
import { GroupSchema, IGroup } from './schema/group.schema';
import { CourseSchema, ICourse } from './schema/course.schema';
import { QuizResultSchema, IQuizResult } from './schema/quizResult.schema';
import { QuizQuestionSchema, IQuizQuestion } from './schema/quizQuestion.schema';
import { GroupRegistrationSchema, IGroupRegistration } from './schema/groupRegistration.schema';
import { CourseRegistrationSchema, ICourseRegistration } from './schema/courseRegistration.schema';

const User: Model<IUser> = mongoose.model<IUser>('User', UserSchema);
const Quiz: Model<IQuiz> = mongoose.model<IQuiz>('Quiz', QuizSchema);
const Group: Model<IGroup> = mongoose.model<IGroup>('Group', GroupSchema);
const Course: Model<ICourse> = mongoose.model<ICourse>('Course', CourseSchema);
const CourseRegistration: Model<ICourseRegistration> = mongoose.model<ICourseRegistration>(
  'CourseRegistration',
  CourseRegistrationSchema
);
const GroupRegistration: Model<IGroupRegistration> = mongoose.model<IGroupRegistration>(
  'GroupRegistration',
  GroupRegistrationSchema
);
const QuizQuestion: Model<IQuizQuestion> = mongoose.model<IQuizQuestion>(
  'QuizQuestion',
  QuizQuestionSchema
);
const QuizResult: Model<IQuizResult> = mongoose.model<IQuizResult>(
  'QuizResult',
  QuizResultSchema
);

export {
  User,
  Quiz,
  Group,
  Course,
  QuizResult,
  QuizQuestion,
  GroupRegistration,
  CourseRegistration,
};