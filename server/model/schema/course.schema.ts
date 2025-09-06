import { Schema, Document } from 'mongoose';

interface ICourse extends Document {
  courseCode: string;
  courseCredit: number;
  courseName: string;
}

const CourseSchema = new Schema<ICourse>(
  {
    courseCode: {
      type: String,
      required: [true, 'Please provide a course code'],
      unique: true,
    },
    courseCredit: {
      type: Number,
      required: [true, 'Please provide course credits'],
      min: [1, 'Course credits must be at least 1'],
    },
    courseName: {
      type: String,
      required: [true, 'Please provide a course name'],
    }
  },
  {
    timestamps: true,
  }
);

export { ICourse, CourseSchema };
