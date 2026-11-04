import application from '../account-backend/src/index.js';
import { createStagingAPI } from './api-wrapper.mjs';
export default createStagingAPI(application);
