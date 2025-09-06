import { Schema, Document, Types } from 'mongoose';

interface IQuizQuestion extends Document {
  quizId: Types.ObjectId;
  questionText: string;
  questionImage?: string;
  options: string[];
  answer: string;
}

const QuizQuestionSchema = new Schema<IQuizQuestion>(
  {
    quizId: {
      type: Schema.Types.ObjectId,
      ref: 'Quiz',
      required: [true, 'Please provide a quiz ID'],
    },
    questionText: {
      type: String,
      required: [true, 'Please provide question text'],
    },
    questionImage: {
      type: String,
      required: false,
    },
    options: {
      type: [String],
      required: [true, 'Please provide answer options'],
      validate: {
        validator: function(options: string[]) {
          return options.length >= 2;
        },
        message: 'At least 2 options are required'
      }
    },
    answer: {
      type: String,
      required: [true, 'Please provide the correct answer'],
      validate: {
        validator: function(answer: string) {
          return this.options.includes(answer);
        },
        message: 'Answer must be one of the provided options'
      }
    }
  },
  {
    timestamps: true,
  }
);

export { IQuizQuestion, QuizQuestionSchema };
