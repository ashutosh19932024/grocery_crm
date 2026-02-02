from channels.generic.websocket import AsyncWebsocketConsumer
import json

class MessageConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if self.scope["user"].is_anonymous:
            # Reject the connection if the user is not authenticated
            await self.close()
        else:
            self.userid = self.scope['url_route']['kwargs']['userid']
            self.room_group_name = f"user_{self.userid}"

            # Join the user's group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )

            await self.accept()

    async def disconnect(self, close_code):
        # Leave the user's group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data['message']
        from_user = data['from_user']
        to_user = data['to_user']

        # Save the message to the database
        from .models import Message
        from uuid import uuid4
        await Message.objects.acreate(
            from_user_id=from_user,
            to_user_id=to_user,
            message=message,
            session_id=data.get('session_id', uuid4())
        )

        # Broadcast the message to the recipient's group
        recipient_group_name = f"user_{to_user}"
        await self.channel_layer.group_send(
            recipient_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'from_user': from_user,
            }
        )

    async def chat_message(self, event):
        message = event['message']
        from_user = event['from_user']

        # Send the message to the WebSocket
        await self.send(text_data=json.dumps({
            'message': message,
            'from_user': from_user,
        }))

class ReceivedMessagesConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Add the user to a group for broadcasting messages
        self.group_name = f"received_messages_{self.scope['user'].userid}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # Remove the user from the group
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # Handle incoming WebSocket messages if needed
        pass

    async def send_message(self, event):
        # Send the received message to the WebSocket
        await self.send(text_data=json.dumps({
            'from_user': event['from_user'],
            'to_user': event['to_user'],
            'message': event['message'],
            'created_date': event['created_date'],
        }))        