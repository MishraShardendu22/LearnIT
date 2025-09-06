import { Schema, Document, Types } from 'mongoose';

interface ICourseRegistration extends Document {
  courseId: Types.ObjectId;
  userId: Types.ObjectId;
}

const CourseRegistrationSchema = new Schema<ICourseRegistration>(
  {
    courseId: {
      type: Schema.Types.ObjectId,
      ref: 'Course',
      required: [true, 'Please provide a course ID'],
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please provide a user ID'],
    }
  },
  {
    timestamps: true,
  }
);

// Create compound index to ensure a user can only register for a course once
CourseRegistrationSchema.index({ courseId: 1, userId: 1 }, { unique: true });

export { ICourseRegistration, CourseRegistrationSchema };
