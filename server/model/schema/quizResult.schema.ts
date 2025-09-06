import { Schema, Document, Types } from 'mongoose';

interface IQuizResult extends Document {
  quizId: Types.ObjectId;
  userId: Types.ObjectId;
  marks: number;
}

const QuizResultSchema = new Schema<IQuizResult>(
  {
    quizId: {
      type: Schema.Types.ObjectId,
      ref: 'Quiz',
      required: [true, 'Please provide a quiz ID'],
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please provide a user ID'],
    },
    marks: {
      type: Number,
      required: [true, 'Please provide marks'],
      min: [0, 'Marks cannot be negative'],
    }
  },
  {
    timestamps: true,
  }
);

// Create compound index to ensure a user can only have one result per quiz
QuizResultSchema.index({ quizId: 1, userId: 1 }, { unique: true });

export { IQuizResult, QuizResultSchema };
