# api/views.py

import os
import traceback
import json
import random
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
import google.generativeai as genai
from PIL import Image
import pytesseract
from pdf2image import convert_from_bytes

from .models import MedicalReport
from .serializers import MedicalReportSerializer, UserSerializer

# --- OCR and AI Configuration ---
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
GOOGLE_GEMINI_MODEL = os.getenv('GOOGLE_GEMINI_MODEL')

if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)

# --- Helper Functions ---
def extract_text_from_file(file_obj):
    """Extracts text from an uploaded image or PDF file."""
    text = ""
    poppler_path = r'C:\poppler\Library\bin'
    
    if file_obj.name.lower().endswith('.pdf'):
        images = convert_from_bytes(file_obj.read(), poppler_path=poppler_path)
        for image in images:
            text += pytesseract.image_to_string(image)
    else:
        image = Image.open(file_obj)
        text = pytesseract.image_to_string(image)
        
    return text

def get_real_ai_analysis(report_text):
    """Sends extracted text to the Gemini AI for analysis."""
    print(f"DEBUG: Attempting to use API Key ending in ...{GOOGLE_API_KEY[-4:]}")
    
    if not GOOGLE_API_KEY:
        return {"error": "AI service is not configured."}

    model = genai.GenerativeModel(GOOGLE_GEMINI_MODEL)
    
    # --- THIS IS THE UPDATED PROMPT ---
    prompt = f"""
    Analyze the following medical report text and provide a structured response in JSON format.
    IMPORTANT: Do not use any Markdown formatting (like **bold** or *italics*) or asterisks (*) in the JSON string values. All text should be plain.

    The JSON object must contain the exact keys from the list below.

    - "description": A detailed, multi-paragraph description of the findings.
    - "medicine_recommendation": A list of suggested over-the-counter medications.
    - "home_remedies": A list of relevant home remedies.
    - "precautions": A list of necessary precautions.
    - "nearby_specialist": Suggest the type of medical specialist to consult (e.g., "Cardiologist", "Endocrinologist").
    - "emergency_video": A URL to a relevant YouTube video for emergencies (e.g., CPR tutorial).
    - "status": A one-word status summary. Your only options are "Normal", "Action Needed", or "High Risk". Choose the most appropriate one.

    Medical Report Text:
    ---
    {report_text}
    ---
    """

    try:
        response = model.generate_content(prompt)
        # Clean the response to ensure it's a valid JSON object
        json_response = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(json_response)
    except Exception as e:
        print(f"AI generation failed: {e}")
        return {"error": f"Failed to get AI analysis. Details: {str(e)}"}

# --- Django Views ---

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create the user but set them as inactive
        user = serializer.save()
        user.is_active = False
        user.save()

        # Generate and send OTP
        otp = str(random.randint(100000, 999999))
        # Store OTP in cache for 5 minutes
        cache.set(f"otp_{user.email}", otp, timeout=300) 

        email_body = f"""
        Hello {user.username},

        Thank you for registering. Your One-Time Password (OTP) is: {otp}

        This code will expire in 5 minutes.
        """
        
        try:
            send_mail(
                'Verify your email address',
                email_body,
                settings.EMAIL_HOST_USER,
                [user.email]
            )
        except Exception as e:
            print(f"Failed to send OTP email: {e}")
            # Optional: handle email sending failure

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class MedicalReportUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        file_obj = request.data.get('report_file')
        
        if not file_obj:
            return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            extracted_text = extract_text_from_file(file_obj)
            if not extracted_text.strip():
                return Response({"error": "Could not read any text from the file..."}, status=status.HTTP_400_BAD_REQUEST)

            analysis_results = get_real_ai_analysis(extracted_text)
            
            if "error" in analysis_results:
                return Response(analysis_results, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            report = MedicalReport.objects.create(
                user=request.user, report_file=file_obj, extracted_text=extracted_text,
                ai_description=analysis_results.get("description", ""),
                ai_medicine_rec=analysis_results.get("medicine_recommendation", ""),
                ai_remedies=analysis_results.get("home_remedies", ""),
                ai_precautions=analysis_results.get("precautions", ""),
                emergency_video_url=analysis_results.get("emergency_video", ""),
                status=analysis_results.get("status", "Pending")
            )
            report.save()
            # Add the extracted_text to the response for the frontend chat context
            analysis_results['extracted_text'] = extracted_text
            return Response(analysis_results, status=status.HTTP_200_OK)
        
        except Exception as e:
            traceback.print_exc()
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MedicalReportListCreateView(generics.ListAPIView):
    serializer_class = MedicalReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return MedicalReport.objects.filter(user=user).order_by('-created_at')

class ChatView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        report_text = request.data.get('report_text')
        chat_history = request.data.get('history', [])
        
        # The user's new question is the last item in the history
        if not chat_history:
            return Response({"error": "No user question provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        user_question = chat_history[-1]['parts'][0]['text'] # Safely access the text

        if not report_text or not user_question:
            return Response({"error": "Report text and a question are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            model = genai.GenerativeModel(GOOGLE_GEMINI_MODEL)
            
            # Contextual prompt for the model
            initial_context = {
                "role": "user",
                "parts": [f"You are a helpful medical assistant. Here is a medical report you have already analyzed: '{report_text}'. Now, please answer my follow-up questions based ONLY on the context of this report. Do not provide general medical advice outside of this report's context."]
            }
            context_response = {
                "role": "model",
                "parts": ["Understood. I have the context of the medical report. I will answer your follow-up questions based on the provided text. Please remember, this is not a substitute for professional medical advice."]
            }
            
            # Combine initial context with previous history (excluding the final user message)
            history_for_chat = [initial_context, context_response] + chat_history[:-1]
            
            chat = model.start_chat(history=history_for_chat)
            
            # Send the new user question
            response = chat.send_message(user_question)
            
            return Response({"response": response.text}, status=status.HTTP_200_OK)

        except Exception as e:
            traceback.print_exc()
            return Response({"error": f"An error occurred with the AI chat: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# In api/views.py, add this at the end

class GeneralChatView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Frontend sends the full history, which includes the last user question
        chat_history = request.data.get('history', [])

        if not chat_history:
            return Response({"error": "No chat history provided."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            model = genai.GenerativeModel(GOOGLE_GEMINI_MODEL)
            
            # FIX: The frontend structure is already correct. We use it directly.
            # Extract the user's latest question text
            user_question = chat_history[-1]['parts'][0]['text']
            
            # History for start_chat should be all previous exchanges (excluding the current user question)
            history_for_chat = chat_history[:-1] 

            # Add general system instruction/context message to the start
            system_instruction = {
                "role": "user",
                "parts": [{"text": "You are a helpful, general medical assistant named Arogya AI. Please keep your answers concise and informative. Never give personalized medical advice, only general information."}]
            }
            context_setter = {
                "role": "model",
                "parts": [{"text": "Understood. I'm ready to answer your general medical questions."}]
            }
            
            full_context_history = [system_instruction, context_setter] + history_for_chat

            # Start the chat session with the full previous history
            chat = model.start_chat(history=full_context_history)
            
            # Send only the new user question (as a plain string)
            response = chat.send_message(user_question)
            
            # FIX: Return the response using the key 'reply' to match ChatWidget.jsx
            return Response({"reply": response.text}, status=status.HTTP_200_OK) 

        except Exception as e:
            traceback.print_exc()
            return Response({"error": f"AI service failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email__iexact=email).first()

        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = f"http://localhost:5173/reset-password/{uid}/{token}/"
            
            email_body = f"""
            Hello,
            Click the link below to reset your password:
            {reset_link}
            If you did not request a password reset, please ignore this email.
            """
            
            try:
                print("\n--- ATTEMPTING TO SEND EMAIL ---")
                print(f"Host: {settings.EMAIL_HOST}")
                print(f"User: {settings.EMAIL_HOST_USER}")
                print("---")

                send_mail(
                    'Password Reset Request',
                    email_body,
                    settings.EMAIL_HOST_USER, # From email
                    [user.email],             # To email
                    fail_silently=False,
                )
                print("--- EMAIL SENT SUCCESSFULLY ---\n")

            except Exception as e:
                print("\n!!!!!! --- EMAIL SENDING FAILED --- !!!!!!")
                print(f"ERROR TYPE: {type(e).__name__}")
                print(f"ERROR DETAILS: {e}")
                print("TROUBLESHOOTING CHECKLIST:")
                print("1. Is EMAIL_USER in your .env file your full, correct Gmail address?")
                print("2. Is EMAIL_PASS the correct 16-digit App Password with NO SPACES?")
                print("3. Have you checked your Gmail for a 'Critical security alert' and approved the sign-in?")
                print("!!!!!! --- END OF ERROR REPORT --- !!!!!!\n")
                pass
            
        return Response({'message': 'If an account with that email exists, a password reset link has been sent.'}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            password = request.data.get('password')
            if not password:
                return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(password)
            user.save()
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid reset link.'}, status=status.HTTP_400_BAD_REQUEST)

# At the end of api/views.py

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        otp_entered = request.data.get('otp')

        if not email or not otp_entered:
            return Response({'error': 'Email and OTP are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        stored_otp = cache.get(f"otp_{email}")
        
        if not stored_otp:
            return Response({'error': 'OTP has expired or is invalid. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        if otp_entered == stored_otp:
            # --- THIS IS THE FIX ---
            # Find the most recent, inactive user with this email address.
            user_to_activate = User.objects.filter(email__iexact=email, is_active=False).order_by('-date_joined').first()

            if user_to_activate:
                user_to_activate.is_active = True
                user_to_activate.save()
                cache.delete(f"otp_{email}") # OTP used, so delete it
                return Response({'message': 'Email verified successfully. You can now log in.'}, status=status.HTTP_200_OK)
            else:
                # This can happen if the user tries to verify an already active account
                return Response({'error': 'No matching inactive user found to verify.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

# At the end of api/views.py
class MedicalReportDeleteView(generics.DestroyAPIView):
    serializer_class = MedicalReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Ensure users can only delete their own reports
        return MedicalReport.objects.filter(user=self.request.user)
