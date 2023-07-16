#ifndef __FSM_H__
#define __FSM_H__

#define STATE_INIT    0
#define STATE_LOADED  1
#define STATE_RUNNING 2

#define FSM_STATE_TRANS(cur_state, next_state) cur_state = next_state;

#endif
