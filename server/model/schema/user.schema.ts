import { Schema, Document } from 'mongoose';

interface IUser extends Document {
  email: string;
  password: string;
  role: 'student' | 'faculty' | 'admin';
}

const UserSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: [true, 'Please provide an email'],
      unique: true
    },
    password: {
      type: String,
      required: [true, 'Please provide a password']
    },
    role: {
      type: String,
      enum: ['student', 'faculty', 'admin'],
      required: [true, 'Please provide a user role']
    }
  },
  {
    timestamps: true,
  }
);

export { IUser, UserSchema };
