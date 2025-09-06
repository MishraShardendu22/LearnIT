import { Schema, Document, Types } from 'mongoose';

interface IGroup extends Document {
  name: string;
  courseId: Types.ObjectId;
  facultyId: Types.ObjectId;
  registrationOpen: boolean;
}

const GroupSchema = new Schema<IGroup>(
  {
    name: {
      type: String,
      required: [true, 'Please provide a group name'],
    },
    courseId: {
      type: Schema.Types.ObjectId,
      ref: 'Course',
      required: [true, 'Please provide a course ID'],
    },
    facultyId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please provide a faculty ID'],
    },
    registrationOpen: {
      type: Boolean,
      default: true,
    }
  },
  {
    timestamps: true,
  }
);

export { IGroup, GroupSchema };
