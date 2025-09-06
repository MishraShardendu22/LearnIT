import { Schema, Document, Types } from 'mongoose';

interface IQuiz extends Document {
  name: string;
  facultyId: Types.ObjectId;
  groupId: Types.ObjectId;
}

const QuizSchema = new Schema<IQuiz>(
  {
    name: {
      type: String,
      required: [true, 'Please provide a quiz name'],
    },
    facultyId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please provide a faculty ID'],
    },
    groupId: {
      type: Schema.Types.ObjectId,
      ref: 'Group',
      required: [true, 'Please provide a group ID'],
    }
  },
  {
    timestamps: true,
  }
);

export { IQuiz, QuizSchema };
